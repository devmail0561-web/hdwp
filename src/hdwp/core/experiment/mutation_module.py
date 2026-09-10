# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MutationModule: transforms a ConcreteExperimentPlan into a mutated NormalizedRequest.

Does NOT execute HTTP -- that is the ExperimentEngine's responsibility.
Each mutation type preserves the original request (model_copy) and applies
only the minimal change required to test the hypothesis.
"""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode, urlparse, urlunparse

from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import ConcreteExperimentPlan, NormalizedRequest

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ── URL helpers (module-level) ────────────────────────────────────────────


def _replace_id_in_path(url: str, new_value: str, param_name: str = "") -> str:
    """Remplace la valeur d'un paramètre de chemin par new_value.

    Si param_name est fourni, essaie de trouver le segment correspondant via
    le pattern normalisé (ex: {user_id} → segment 3 de /api/orgs/42/users/7).
    Sinon remplace le premier segment numérique/UUID trouvé (comportement legacy).
    """
    parsed = urlparse(url)
    parts = parsed.path.split("/")

    # Stratégie 1 : utiliser le nom du paramètre pour cibler le bon segment
    if param_name:
        param_lower = param_name.lower()
        # Extraire le préfixe sémantique : video_id → video, user_id → user
        # Utiliser rsplit pour éviter de corrompre les noms avec 'id' en substring
        # (video_id → video, NOT veo comme avec double replace)
        if "_id" in param_lower:
            base = param_lower.rsplit("_id", 1)[0]
        elif param_lower.endswith("id"):
            base = param_lower[:-2].rstrip("_")
        else:
            base = param_lower
        if base:
            for i, part in enumerate(parts):
                if i > 0 and (_NUMERIC.match(part) or _UUID.match(part)):
                    prev = parts[i - 1].lower().rstrip("s")  # users→user, orgs→org
                    if base in prev or prev in base or prev.startswith(base) or base.startswith(prev):
                        parts[i] = new_value
                        return urlunparse(parsed._replace(path="/".join(parts)))

    # Stratégie 2 (fallback) : remplacer le premier segment numérique/UUID
    for i, part in enumerate(parts):
        if _NUMERIC.match(part) or _UUID.match(part):
            parts[i] = new_value
            break
    return urlunparse(parsed._replace(path="/".join(parts)))


def _rebuild_url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params)))


# ── Apply functions (module-level) ──────────────────────────────────────────


def apply_identity_swap(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Replace auth headers with target_role credentials."""
    if plan.target_role is None:
        return plan.baseline_request
    new_headers = sm.prepare_headers(plan.target_role, plan.baseline_request.headers)
    return plan.baseline_request.model_copy(update={"headers": new_headers})


def apply_object_ref_change(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Change the value of mutated_param_name in path / query / body."""
    if plan.mutated_value is None or plan.mutated_param_name is None:
        return plan.baseline_request
    req = plan.baseline_request

    match plan.mutated_param_location:
        case "path":
            new_url = _replace_id_in_path(req.url, plan.mutated_value, plan.mutated_param_name or "")
            return req.model_copy(update={"url": new_url})
        case "query":
            new_params = {**req.query_params, plan.mutated_param_name: plan.mutated_value}
            new_url = _rebuild_url_with_params(req.url, new_params)
            return req.model_copy(update={"url": new_url, "query_params": new_params})
        case "body" if isinstance(req.body, dict):
            new_body = {**req.body, plan.mutated_param_name: plan.mutated_value}
            return req.model_copy(update={"body": new_body})
        case _:
            return req


def apply_privilege_escalation(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Access a restricted endpoint with an unauthorised role's credentials.

    Identical credential-swap logic as identity_swap; re-uses that implementation.
    """
    return apply_identity_swap(plan, sm)


def _inject_nested(body: dict, param: str, payload: str) -> dict:
    """Injecte le payload au niveau racine ET dans les sous-objets courants."""
    new_body = {**body, param: payload}
    for k in ("filter", "query", "where", "data", "user", "input", "params", "criteria"):
        if k in body and isinstance(body[k], dict):
            new_body[k] = {**body[k], param: payload}
            break
    return new_body


def apply_field_injection(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Inject a payload into the target parameter at the specified location.

    Supports: query, body (dict imbriqué), body (str), path, header, cookie.
    """
    req = plan.baseline_request
    payload = plan.mutated_value or ""
    param = plan.mutated_param_name or ""
    location = plan.mutated_param_location or "query"
    payload_type = (plan.experiment_spec.mutation_params.get("payload_type", "")
                    if plan.experiment_spec else "")

    # Path traversal location=path : encoder pour tester les filtres naïfs
    # IMPORTANT : N'encoder QUE pour location="path" — pour location="query",
    # _rebuild_url_with_params appelle urlencode() qui re-encoderait les % → %25 (double-encoding)
    if payload_type == "path_traversal" and "../" in payload and location == "path":
        payload = quote(payload, safe="")

    match location:
        case "query":
            new_params = {**req.query_params, param: payload}
            new_url = _rebuild_url_with_params(req.url, new_params)
            return req.model_copy(update={"url": new_url, "query_params": new_params})
        case "body" if isinstance(req.body, dict):
            new_body = _inject_nested(req.body, param, payload)
            return req.model_copy(update={"body": new_body})
        case "body" if isinstance(req.body, str):
            return req.model_copy(update={"body": req.body + payload})
        case "path":
            new_url = _replace_id_in_path(req.url, payload, param)
            return req.model_copy(update={"url": new_url})
        case "header":
            header_name = param or "X-Injected"
            new_headers = {**dict(req.headers or {}), header_name: payload}
            return req.model_copy(update={"headers": new_headers})
        case "cookie":
            # Injection dans un cookie — IDOR, SQLi, session fixation via cookie
            existing = dict(req.headers or {}).get("Cookie", "")
            pairs = dict(
                p.strip().split("=", 1) for p in existing.split(";") if "=" in p
            ) if existing else {}
            pairs[param] = payload
            new_cookie = "; ".join(f"{k}={v}" for k, v in pairs.items())
            new_headers = {**dict(req.headers or {}), "Cookie": new_cookie}
            return req.model_copy(update={"headers": new_headers})
        case _:
            return req


def apply_jwt_manipulation(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Forge a manipulated JWT token and inject it into the Authorization header."""
    from hdwp.core.experiment.jwt_mutator import forge_alg_none, forge_expired, try_weak_secrets

    req = plan.baseline_request
    attack = plan.experiment_spec.mutation_params.get("jwt_attack", "alg_none")
    token = sm.build_auth_headers(plan.baseline_role).get("Authorization", "").replace("Bearer ", "")
    if not token:
        return req

    forged: str | None = None
    match attack:
        case "alg_none":
            forged = forge_alg_none(token)
        case "expired_token":
            forged = forge_expired(token)
        case "weak_secret":
            forged = try_weak_secrets(token)

    if forged is None:
        return req
    new_headers = {**req.headers, "Authorization": f"Bearer {forged}"}
    return req.model_copy(update={"headers": new_headers})


def apply_origin_test(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Add a malicious Origin header to test CORS policy."""
    evil_origin = plan.experiment_spec.mutation_params.get(
        "evil_origin", "https://evil.hdwp-test.invalid"
    )
    new_headers = {**plan.baseline_request.headers, "Origin": evil_origin}
    return plan.baseline_request.model_copy(update={"headers": new_headers})


def apply_method_override(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Ajoute X-HTTP-Method-Override header pour contourner le contrôle de méthode."""
    override_method = plan.experiment_spec.mutation_params.get("override_method", "DELETE")
    new_headers = {
        **plan.baseline_request.headers,
        "X-HTTP-Method-Override": override_method,
        "X-HTTP-Method": override_method,
        "X-Method-Override": override_method,
    }
    return plan.baseline_request.model_copy(
        update={"method": "GET", "headers": new_headers}
    )


def apply_race_condition(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Return baseline request unmodified — concurrency handled by TemporalModule."""
    return plan.baseline_request


def apply_token_reuse(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Return baseline request unmodified — replay logic handled by TemporalModule."""
    return plan.baseline_request


def apply_path_traversal(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte le payload path traversal avec variantes d'encodage.

    Teste ../../etc/passwd, puis %2e%2e%2f (URL-encoded), puis ..%2F (mixed).
    """
    req = plan.baseline_request
    payload = plan.mutated_value or "../../../etc/passwd"
    param = plan.mutated_param_name or ""
    location = plan.mutated_param_location or "query"

    # Choisir la variante d'encodage selon l'indice du plan dans la séquence
    # (le même payload est tenté avec différents encodages via plusieurs specs)
    payload_type = (plan.experiment_spec.mutation_params.get("payload_type", "")
                    if plan.experiment_spec else "")
    if payload_type == "path_traversal_encoded":
        payload = quote(payload, safe="")
    elif payload_type == "path_traversal_mixed":
        payload = payload.replace("../", "..%2F")
    elif payload_type == "path_traversal_double":
        payload = payload.replace("../", "....//")

    if location == "query" and param:
        # Pour query: ne PAS pré-encoder — urlencode() s'en charge déjà (évite double-encoding)
        raw_payload = plan.mutated_value or "../../../etc/passwd"
        if payload_type in ("path_traversal_mixed",):
            raw_payload = raw_payload.replace("../", "..%2F")
        elif payload_type in ("path_traversal_double",):
            raw_payload = raw_payload.replace("../", "....//")
        new_params = {**req.query_params, param: raw_payload}
        return req.model_copy(update={"url": _rebuild_url_with_params(req.url, new_params),
                                       "query_params": new_params})
    if location == "body" and isinstance(req.body, dict) and param:
        return req.model_copy(update={"body": _inject_nested(req.body, param, payload)})
    if location == "path" and param:
        # Pour path: appliquer l'encodage directement sur le segment d'URL
        new_url = _replace_id_in_path(req.url, payload, param)
        return req.model_copy(update={"url": new_url})
    return apply_field_injection(plan, sm)


def apply_nosqli(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte des opérateurs MongoDB dans le corps JSON ou les paramètres.

    Contrairement à field_injection qui insère une string, nosqli insère
    un objet operator : {"$gt": ""} ou {"$regex": ".*"} comme valeur.
    """
    req = plan.baseline_request
    param = plan.mutated_param_name or ""
    location = plan.mutated_param_location or "query"
    raw_payload = plan.mutated_value or '{"$gt": ""}'

    # Tenter de parser le payload comme dict MongoDB
    import json as _json
    try:
        operator = _json.loads(raw_payload)
    except Exception:
        operator = {"$gt": ""}

    if location == "body" and isinstance(req.body, dict) and param:
        new_body = {**req.body, param: operator}
        return req.model_copy(update={"body": new_body})
    if location == "query" and param:
        # Pour query string, sérialiser l'opérateur en JSON
        new_params = {**req.query_params, param: _json.dumps(operator)}
        return req.model_copy(update={"url": _rebuild_url_with_params(req.url, new_params),
                                       "query_params": new_params})
    return apply_field_injection(plan, sm)


def apply_open_redirect(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte une URL malveillante dans les paramètres de redirection.

    Teste la redirection absolue, le double-slash, et l'URL-encoded.
    """
    req = plan.baseline_request
    param = plan.mutated_param_name or "redirect"
    location = plan.mutated_param_location or "query"
    evil_url = plan.mutated_value or "https://evil.hdwp-test.invalid"

    if location == "query":
        new_params = {**req.query_params, param: evil_url}
        return req.model_copy(update={"url": _rebuild_url_with_params(req.url, new_params),
                                       "query_params": new_params})
    if location == "body" and isinstance(req.body, dict):
        new_body = {**req.body, param: evil_url}
        return req.model_copy(update={"body": new_body})
    return apply_field_injection(plan, sm)


def apply_type_confusion(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Envoie une valeur du mauvais type pour détecter les absences de validation.

    Un serveur qui retourne 200 à une confusion de type manque de validation —
    exploitable via PHP type juggling, comparaisons lâches JS, bypasses logiques.
    """
    import json as _json
    req = plan.baseline_request
    param = plan.mutated_param_name or ""
    location = plan.mutated_param_location or "query"
    raw = plan.mutated_value
    if raw is None:
        return req
    # Le planner stocke la valeur confuse sérialisée en JSON
    try:
        confused_value = _json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        confused_value = raw

    match location:
        case "query":
            new_params = {**req.query_params, param: str(confused_value) if confused_value is not None else "null"}
            return req.model_copy(update={
                "url": _rebuild_url_with_params(req.url, new_params),
                "query_params": new_params,
            })
        case "body" if isinstance(req.body, dict):
            new_body = {**req.body, param: confused_value}
            return req.model_copy(update={"body": new_body})
        case _:
            return req


def apply_boundary_value(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte des valeurs limites pour détecter dépassements, nulls, buffers.

    Détecte des comportements inattendus sans connaître le type de vulnérabilité.
    """
    import json as _json
    req = plan.baseline_request
    param = plan.mutated_param_name or ""
    location = plan.mutated_param_location or "query"
    raw = plan.mutated_value
    try:
        value = _json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        value = raw

    match location:
        case "query":
            str_val = str(value) if value is not None else "null"
            new_params = {**req.query_params, param: str_val}
            return req.model_copy(update={
                "url": _rebuild_url_with_params(req.url, new_params),
                "query_params": new_params,
            })
        case "body" if isinstance(req.body, dict):
            new_body = {**req.body, param: value}
            return req.model_copy(update={"body": new_body})
        case _:
            return req


def apply_parameter_pollution(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte des champs supplémentaires inattendus pour détecter mass assignment,
    exposition de champs cachés, et anomalies de parsing d'input.
    """
    import json as _json
    req = plan.baseline_request
    raw_extra = (plan.experiment_spec.mutation_params.get("extra_fields", "")
                 if plan.experiment_spec else "")
    try:
        extra_fields: dict = _json.loads(raw_extra) if raw_extra else {}
    except Exception:
        extra_fields = {}

    if not extra_fields:
        extra_fields = {
            "is_admin": True,
            "role": "admin",
            "__proto__": {"isAdmin": True},
            "_debug": True,
        }

    if isinstance(req.body, dict):
        return req.model_copy(update={"body": {**req.body, **extra_fields}})

    new_params = {**req.query_params, **{k: str(v) for k, v in extra_fields.items()}}
    return req.model_copy(update={
        "url": _rebuild_url_with_params(req.url, new_params),
        "query_params": new_params,
    })


def apply_http_method_fuzzing(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Change la méthode HTTP de la requête baseline."""
    new_method = plan.mutated_value or "POST"
    req = plan.baseline_request
    new_headers = dict(req.headers or {})
    if new_method in ("POST", "PUT", "PATCH") and "content-type" not in {k.lower() for k in new_headers}:
        new_headers["Content-Type"] = "application/json"
    body = req.body
    if new_method in ("POST", "PUT", "PATCH") and body is None:
        body = {}
    return req.model_copy(update={"method": new_method, "headers": new_headers, "body": body})


def apply_cache_poisoning(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte X-Forwarded-Host et variantes pour empoisonner le cache."""
    evil_host = plan.mutated_value or "evil.hdwp-test.invalid"
    new_headers = {
        **plan.baseline_request.headers,
        "X-Forwarded-Host": evil_host,
        "X-Original-URL": "/",
        "X-Rewrite-URL": "/",
    }
    return plan.baseline_request.model_copy(update={"headers": new_headers})


def apply_http_smuggling(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """CL.TE probe : Content-Length + Transfer-Encoding conflictuels."""
    smuggle_body = b"0\r\n\r\nGET /hdwp-smuggle-probe HTTP/1.1\r\nHost: localhost\r\n\r\n"
    new_headers = {
        **plan.baseline_request.headers,
        "Transfer-Encoding": "chunked",
        "Content-Length": str(len(smuggle_body)),
    }
    return plan.baseline_request.model_copy(update={
        "method": "POST",
        "headers": new_headers,
        "raw_body_override": smuggle_body,
    })


def apply_info_disclosure(plan: ConcreteExperimentPlan, sm: SessionManager) -> NormalizedRequest:
    """Injecte des caractères d'erreur dans un paramètre pour provoquer un stack trace."""
    req = plan.baseline_request
    payload = plan.mutated_value or "'\"<>%00"
    param_name = plan.mutated_param_name
    param_location = plan.mutated_param_location or "query"

    if param_location == "query":
        new_params = dict(req.query_params)
        if param_name:
            new_params[param_name] = payload
        else:
            new_params["hdwp_probe"] = payload
        return req.model_copy(update={
            "url": _rebuild_url_with_params(req.url, new_params),
            "query_params": new_params,
        })
    elif param_location == "body" and isinstance(req.body, dict):
        new_body = dict(req.body)
        new_body[param_name or "hdwp_probe"] = payload
        return req.model_copy(update={"body": new_body})
    return req.model_copy(update={
        "url": _rebuild_url_with_params(req.url, {**req.query_params, "hdwp_probe": payload}),
        "query_params": {**req.query_params, "hdwp_probe": payload},
    })


class MutationModule:
    """
    Applies a mutation to a reference request according to the provided plan.
    Returns a new NormalizedRequest ready to be sent.
    """

    def apply(
        self,
        plan: ConcreteExperimentPlan,
        session_manager: SessionManager,
    ) -> NormalizedRequest:
        from hdwp.core import mutation_registry

        result = mutation_registry.apply(plan.mutation_type, plan, session_manager)
        if result is None:
            result = plan.baseline_request

        # Phase 2: Apply transport-level WAF bypass if specified in mutation_params.
        # Only activates when _transport_bypass key is present — zero regression for existing mutations.
        transport_bypass: str | None = (
            plan.experiment_spec.mutation_params.get("_transport_bypass")
            if plan.experiment_spec
            else None
        )
        if transport_bypass:
            try:
                from hdwp.core.payloads.waf_bypass.bypass_registry import get_bypass_registry
                bypass_result = get_bypass_registry().apply_bypass(
                    transport_bypass,
                    result,
                    dict(plan.experiment_spec.mutation_params),
                )
                if bypass_result.raw_override is not None:
                    result = bypass_result.request.model_copy(
                        update={"raw_body_override": bypass_result.raw_override}
                    )
                else:
                    result = bypass_result.request
            except Exception as exc:
                import structlog as _structlog
                _structlog.get_logger().debug(
                    "mutation.transport_bypass_failed",
                    bypass=transport_bypass,
                    error=str(exc),
                )

        return result
