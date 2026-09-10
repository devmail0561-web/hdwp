# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
RequestSelector: bridges the gap between abstract ExperimentSpec and concrete HTTP requests.

Given a Hypothesis and the ApplicationModel's request corpus, produces
ConcreteExperimentPlan objects the ExperimentEngine can execute directly.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConcreteExperimentPlan,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
)

# ── Module-level compiled patterns ────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ── Helper functions (module-level) ────────────────────────────────────────


def extract_param_value(
    req: NormalizedRequest,
    param_name: str,
    location: str,
    path_pattern: str,
) -> str | None:
    if location == "query":
        return req.query_params.get(param_name)
    if location == "body" and isinstance(req.body, dict):
        v = req.body.get(param_name)
        return str(v) if v is not None else None
    if location == "path":
        return extract_path_value(req.url, path_pattern, param_name)
    return None


def extract_path_value(url: str, path_pattern: str, param_name: str) -> str | None:
    """
    Match concrete URL segments against path pattern placeholders
    and return the value for the requested parameter slot.
    """
    url_parts = urlparse(url).path.strip("/").split("/")
    pat_parts = path_pattern.strip("/").split("/")
    if len(url_parts) != len(pat_parts):
        return None
    for url_seg, pat_seg in zip(url_parts, pat_parts):
        if pat_seg.startswith("{") and pat_seg.endswith("}"):
            slot = pat_seg[1:-1]  # e.g. "id_0"
            # Match the slot name to the requested parameter name.
            # Exact name match or substring match covers most cases.
            # Index-based match: normalizer names path params "path_N" while the
            # model assigns slot names like "id_N" — both embed the ordinal N.
            # When param_name is "path_N" and slot ends with "_N" (or just "N"),
            # match by the shared numeric suffix instead of defaulting to the
            # first placeholder (the original `startswith("path_")` catch-all was
            # too broad and returned the wrong segment for multi-segment paths).
            _index_match = False
            if param_name.startswith("path_"):
                _suffix = param_name[len("path_"):]
                if _suffix.isdigit() and (slot.endswith("_" + _suffix) or slot == _suffix):
                    _index_match = True
            if param_name == slot or param_name in slot or slot in param_name or _index_match:
                return url_seg
    return None


def find_request_with_param(
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    role_name: str,
    param_name: str,
    location: str,
    value: str,
) -> NormalizedRequest | None:
    for requests in corpus.values():
        for r_name, req in requests:
            if r_name != role_name:
                continue
            if location == "query" and req.query_params.get(param_name) == value:
                return req
            if location == "body" and isinstance(req.body, dict) and str(req.body.get(param_name, "")) == value:
                return req
            if location == "path":
                # Compare path segments exactly, not as a substring of the full URL.
                # A substring check like `value in req.url` would wrongly match "1"
                # in any URL that contains the digit 1 (e.g. /v1/admin/).
                url_path = urlparse(req.url).path
                if value in url_path.split("/"):
                    return req
    return None


def fallback_probe_values(current_value: str) -> list[str]:
    """
    Genere plusieurs valeurs candidates quand un seul role est observe.
    Couvre : integers sequentiels + petits IDs + UUIDs aleatoires.
    """
    probes: list[str] = []

    # Integers : N-1, 1, 2, 3, N+1 (sans inclure N ni les negatifs)
    try:
        n = int(current_value)
        candidates: set[int] = {n - 1, n + 1, 1, 2, 3}
        candidates.discard(n)
        candidates.discard(0)
        candidates.discard(-1)
        probes.extend(str(c) for c in sorted(candidates) if c > 0)
    except ValueError:
        pass

    # UUIDs : generer 2 UUID v4 aleatoires
    if _UUID_RE.match(current_value):
        probes.append(str(uuid.uuid4()))
        probes.append(str(uuid.uuid4()))

    return probes[:3]  # max 3 probes pour limiter le flood


# ── Planification functions (module-level) ──────────────────────────────────


def plan_identity_swap(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """
    For each path_pattern where >=2 non-anonymous roles have observed requests,
    produce one plan: replay role_a's request with role_b's identity.
    """
    plans: list[ConcreteExperimentPlan] = []
    named_roles = [r.name for r in model.roles if r.name != "anonymous"]
    if len(named_roles) < 2:
        return plans

    for requests in corpus.values():
        by_role: dict[str, list[NormalizedRequest]] = {}
        for role_name, req in requests:
            by_role.setdefault(role_name, []).append(req)

        present = [r for r in named_roles if r in by_role]
        if len(present) < 2:
            continue

        role_a, role_b = present[0], present[1]
        baseline = by_role[role_a][0]
        plans.append(ConcreteExperimentPlan(
            hypothesis_id=hyp.id,
            mutation_type="identity_swap",
            baseline_request=baseline,
            baseline_role=role_a,
            target_role=role_b,
            mutated_value=None,
            mutated_param_name=None,
            mutated_param_location=None,
            description=(
                f"Replay {baseline.method} {baseline.url} "
                f"replacing '{role_a}' credentials with '{role_b}'"
            ),
            experiment_spec=spec,
        ))

    return plans


def plan_object_ref_change(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """
    For each role pair, try to access an object ID owned by the other role.
    Falls back to a sequential +1 probe when only one role is present.
    """
    plans: list[ConcreteExperimentPlan] = []
    param_name = spec.mutation_params.get("parameter_name", "")
    param_location = spec.mutation_params.get("parameter_location", "path")

    # Collect observed parameter values per role
    values_by_role: dict[str, list[str]] = {}
    for path_pattern, requests in corpus.items():
        for role_name, req in requests:
            val = extract_param_value(req, param_name, param_location, path_pattern)
            if val is not None:
                bucket = values_by_role.setdefault(role_name, [])
                if val not in bucket:
                    bucket.append(val)
                if len(bucket) > 5:
                    bucket[:] = bucket[:5]

    roles = list(values_by_role)
    if not roles:
        return plans

    # Cross-role: role_a tries role_b's object
    for role_a in roles:
        for role_b in roles:
            if role_b == role_a:
                continue
            vals_a = values_by_role[role_a]
            vals_b = values_by_role[role_b]
            if not vals_a or not vals_b:
                continue
            # Find the first value owned by role_b that role_a has NOT observed.
            # Limiting to vals_b[0] misses private resources at higher indices when
            # the first value is a shared/public resource also seen by role_a.
            vals_a_set = set(vals_a)
            target_val = next((v for v in vals_b if v not in vals_a_set), None)
            if target_val is None:
                continue
            baseline = find_request_with_param(
                corpus, role_a, param_name, param_location, vals_a[0]
            )
            if baseline is None:
                continue
            plans.append(ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="object_ref_change",
                baseline_request=baseline,
                baseline_role=role_a,
                target_role=None,
                mutated_value=target_val,
                mutated_param_name=param_name,
                mutated_param_location=param_location,
                description=(
                    f"Access {param_name}={target_val} "
                    f"(owned by '{role_b}') using '{role_a}' credentials"
                ),
                experiment_spec=spec,
            ))

    # Fallback: multi-probe strategy when only one role observed
    if not plans and len(roles) == 1:
        role = roles[0]
        vals = values_by_role[role]
        if vals:
            baseline = find_request_with_param(
                corpus, role, param_name, param_location, vals[0]
            )
            if baseline is not None:
                for probe_val in fallback_probe_values(vals[0]):
                    plans.append(ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="object_ref_change",
                        baseline_request=baseline,
                        baseline_role=role,
                        target_role=None,
                        mutated_value=probe_val,
                        mutated_param_name=param_name,
                        mutated_param_location=param_location,
                        description=(
                            f"Probe {param_name}={probe_val} "
                            f"(inference depuis {vals[0]})"
                        ),
                        experiment_spec=spec,
                    ))

    return plans


def plan_privilege_escalation(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """
    Find an observed request for the restricted endpoint and plan access
    with the lower-privilege target_role.
    """
    plans: list[ConcreteExperimentPlan] = []
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    target_role = spec.mutation_params.get("target_role", "")
    if not endpoint_path or not target_role:
        return plans

    prefix = endpoint_path.split("{")[0]
    for path_pattern, requests in corpus.items():
        if path_pattern != endpoint_path and not path_pattern.startswith(prefix):
            continue
        if not requests:
            continue
        obs_role, baseline = requests[0]
        # Skip tautological plans: if the observed role is the same as the
        # target_role, we'd replay the request with identical credentials and
        # the oracle would see no difference — producing a false negative.
        if obs_role == target_role:
            continue
        # Utiliser la méthode réelle de la requête observée dans le corpus.
        # spec.base_request.method est "" (vide) par convention — ne pas fallback sur "GET"
        # si le corpus a une vraie méthode (POST, PUT, DELETE…).
        method = baseline.method if baseline.method else "GET"
        plans.append(ConcreteExperimentPlan(
            hypothesis_id=hyp.id,
            mutation_type="privilege_escalation",
            baseline_request=NormalizedRequest(
                method=method,
                url=baseline.url,
                headers=dict(baseline.headers),
                body=baseline.body,
                query_params=dict(baseline.query_params),
                path_params=dict(baseline.path_params),
            ),
            baseline_role=obs_role,
            target_role=target_role,
            mutated_value=None,
            mutated_param_name=None,
            mutated_param_location=None,
            description=f"Access '{endpoint_path}' with unauthorized role '{target_role}'",
            experiment_spec=spec,
        ))
        break  # one plan per endpoint is sufficient

    return plans


def plan_field_injection(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """
    Pour field_injection : trouver une requete observee qui utilise le parametre
    cible, puis planifier l'injection du payload dedans.

    Fallback : si aucune requete n'a ce parametre, utiliser la premiere requete
    disponible dans le corpus (permet de tester meme sans observation prealable).
    """
    param_name = spec.mutation_params.get("parameter_name", "")
    param_location = spec.mutation_params.get("parameter_location", "query")
    payload = spec.mutation_params.get("payload", "")
    payload_type = spec.mutation_params.get("payload_type", "sqli")

    if not payload:
        return []

    endpoint_path = spec.mutation_params.get("endpoint_path", "")

    def _make_plan(req: NormalizedRequest, role_name: str) -> ConcreteExperimentPlan:
        return ConcreteExperimentPlan(
            hypothesis_id=hyp.id,
            mutation_type="field_injection",
            baseline_request=req,
            baseline_role=role_name,
            target_role=None,
            mutated_value=payload,
            mutated_param_name=param_name,
            mutated_param_location=param_location,
            description=f"Inject {payload_type.upper()} into '{param_name}': {payload[:30]}",
            experiment_spec=spec,
        )

    # Priorité 1 : endpoint_path connu → chercher d'abord dans cet endpoint
    if endpoint_path:
        for path, requests in corpus.items():
            if endpoint_path not in path and path not in endpoint_path:
                continue
            for role_name, req in requests:
                value = extract_param_value(req, param_name, param_location, path)
                if value is not None:
                    return [_make_plan(req, role_name)]
        # Paramètre non observé sur cet endpoint mais endpoint dans le corpus :
        # utiliser la requête de base de cet endpoint et laisser l'applier injecter le param.
        for path, requests in corpus.items():
            if endpoint_path in path or path in endpoint_path:
                if requests:
                    role_name, req = requests[0]
                    return [_make_plan(req, role_name)]

    # Priorité 2 : pas d'endpoint connu → chercher le param dans tout le corpus
    for path, requests in corpus.items():
        for role_name, req in requests:
            value = extract_param_value(req, param_name, param_location, path)
            if value is not None:
                return [_make_plan(req, role_name)]

    # Priorité 3 : le modèle connaît des méthodes non-GET pour cet endpoint
    # (découvertes via OPTIONS ou OpenAPI) → créer des baselines synthétiques
    # Cela permet de tester POST/PUT/DELETE même quand seul GET a été observé.
    if endpoint_path and model:
        for ep in model.endpoints:
            if endpoint_path not in ep.path and ep.path not in endpoint_path:
                continue
            non_get_methods = [m for m in ep.methods if m not in ("GET", "HEAD", "OPTIONS")]
            if not non_get_methods:
                continue
            # Chercher n'importe quelle entrée corpus pour cet endpoint (même GET)
            for path, requests in corpus.items():
                if endpoint_path not in path and path not in endpoint_path:
                    continue
                if not requests:
                    continue
                role_name, base_req = requests[0]
                plans = []
                for ep_method in non_get_methods[:3]:  # max 3 méthodes
                    # Créer une baseline synthétique avec la méthode correcte
                    body_placeholder: dict | None = None
                    if ep_method in ("POST", "PUT", "PATCH") and param_location == "body":
                        body_placeholder = {param_name: "placeholder"}
                    synthetic = base_req.model_copy(update={
                        "method": ep_method,
                        "body": body_placeholder if body_placeholder else base_req.body,
                    })
                    plans.append(_make_plan(synthetic, role_name))
                if plans:
                    return plans

    return []


def plan_jwt_manipulation(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """JWT manipulation: use any authenticated endpoint as baseline."""
    target_path = spec.mutation_params.get("target_endpoint", "")

    # Prefer the target endpoint, fall back to any authenticated request
    for path, requests in corpus.items():
        if not requests:
            continue
        if not target_path or path == target_path or path.startswith(target_path.split("{")[0]):
            role_name, req = requests[0]
            if role_name != "anonymous":
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="jwt_manipulation",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=None,
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=spec.description,
                    experiment_spec=spec,
                )]

    # Fallback: any non-anonymous request
    for requests in corpus.values():
        for role_name, req in requests:
            if role_name != "anonymous":
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="jwt_manipulation",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=None,
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=spec.description,
                    experiment_spec=spec,
                )]
    return []


def plan_origin_test(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """CORS origin test: any endpoint request works as baseline."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    evil_origin = spec.mutation_params.get("evil_origin", "https://evil.hdwp-test.invalid")

    for path, requests in corpus.items():
        if not requests:
            continue
        if not endpoint_path or path == endpoint_path or path.startswith(endpoint_path.split("{")[0]):
            role_name, req = requests[0]
            return [ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="origin_test",
                baseline_request=req,
                baseline_role=role_name,
                target_role=None,
                mutated_value=evil_origin,
                mutated_param_name=None,
                mutated_param_location=None,
                description=f"CORS test: Origin: {evil_origin}",
                experiment_spec=spec,
            )]
    return []


def plan_race_condition(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Race condition test: select write endpoint matching race keywords."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    concurrency = spec.mutation_params.get("concurrency", 10)

    for path, requests in corpus.items():
        if not requests:
            continue
        if endpoint_path and (path == endpoint_path or path.startswith(endpoint_path.split("{")[0])):
            role_name, req = requests[0]
            # Only write operations
            if req.method in ("POST", "PUT", "PATCH"):
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="race_condition",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=str(concurrency),
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=f"Race condition: {concurrency} concurrent requests on {path}",
                    experiment_spec=spec,
                )]
    return []


def plan_token_reuse(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Token reuse test: find authenticated endpoint + logout endpoint."""
    auth_endpoint = spec.mutation_params.get("authenticated_endpoint", "")
    logout_endpoint = spec.mutation_params.get("logout_endpoint", "")

    # Find authenticated request
    for path, requests in corpus.items():
        if not requests:
            continue
        if auth_endpoint and (path == auth_endpoint or path.startswith(auth_endpoint.split("{")[0])):
            for role_name, req in requests:
                # Must have auth header
                if "authorization" in {k.lower() for k in req.headers.keys()}:
                    return [ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="token_reuse",
                        baseline_request=req,
                        baseline_role=role_name,
                        target_role=None,
                        mutated_value=logout_endpoint,
                        mutated_param_name=None,
                        mutated_param_location=None,
                        description=f"Token reuse: replay after logout on {path}",
                        experiment_spec=spec,
                    )]
    return []


def plan_method_override(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Method override: find GET requests for the target endpoint and add override headers."""
    override_method = spec.mutation_params.get("override_method", "DELETE")
    target_path = spec.mutation_params.get("endpoint_path", "")
    plans = []
    for path_pattern, entries in corpus.items():
        if target_path and target_path not in path_pattern:
            continue
        for role_name, req in entries[:2]:
            if req.method.upper() == "GET":
                plans.append(ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="method_override",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=override_method,
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=f"Method override: GET+{override_method} on {path_pattern}",
                    experiment_spec=spec,
                ))
    return plans[:3]


HTTP_METHODS_TO_FUZZ = ["POST", "PUT", "DELETE", "PATCH"]


def plan_http_method_fuzzing(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Pour chaque endpoint découvert, tester toutes les méthodes HTTP."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    plans = []
    seen_patterns: set[str] = set()

    for path_pattern, entries in corpus.items():
        if endpoint_path and endpoint_path not in path_pattern:
            continue
        if path_pattern in seen_patterns:
            continue
        seen_patterns.add(path_pattern)
        if not entries:
            continue
        role_name, req = entries[0]
        for method in HTTP_METHODS_TO_FUZZ:
            if req.method.upper() == method:
                continue
            plans.append(ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="http_method_fuzzing",
                baseline_request=req,
                baseline_role=role_name,
                target_role=None,
                mutated_value=method,
                mutated_param_name=None,
                mutated_param_location=None,
                description=f"Method fuzzing: {method} on {path_pattern}",
                experiment_spec=spec,
            ))
    return plans[:20]


class RequestSelector:
    """
    Resolves abstract ExperimentSpec objects into ConcreteExperimentPlan objects
    by matching them against the ApplicationModel's observed request corpus.
    """

    def select_for_hypothesis(
        self,
        hyp: Hypothesis,
        model_snapshot: ApplicationModelData,
        request_corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """Return concrete experiment plans for all ExperimentSpecs in the hypothesis."""
        from hdwp.core import mutation_registry

        plans: list[ConcreteExperimentPlan] = []
        for spec in hyp.required_experiments:
            plans.extend(
                mutation_registry.plan(
                    spec.mutation_type, hyp, spec, model_snapshot, request_corpus
                )
            )
        return plans

    def select_for_spec(
        self,
        spec: ExperimentSpec,
        hyp: Hypothesis,
        model_snapshot: ApplicationModelData,
        request_corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """Résout un seul ExperimentSpec en ConcreteExperimentPlans.

        Utilisé par l'engine pour les follow-up specs activés dynamiquement
        pendant la boucle d'exécution (expériences adaptatives).
        """
        from hdwp.core import mutation_registry

        return mutation_registry.plan(
            spec.mutation_type, hyp, spec, model_snapshot, request_corpus
        )

def plan_cache_poisoning(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Cache poisoning: inject X-Forwarded-Host on any cached endpoint."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    evil_host = spec.mutation_params.get("evil_host", "evil.hdwp-test.invalid")

    for path, requests in corpus.items():
        if not requests:
            continue
        if not endpoint_path or endpoint_path in path or path in endpoint_path:
            role_name, req = requests[0]
            if req.method in ("GET", "HEAD"):
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="cache_poisoning",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=evil_host,
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=f"Cache poisoning: X-Forwarded-Host: {evil_host} on {path}",
                    experiment_spec=spec,
                )]
    return []


def plan_http_smuggling(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """HTTP smuggling: CL.TE / TE.CL probe on any endpoint."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")

    for path, requests in corpus.items():
        if not requests:
            continue
        if not endpoint_path or endpoint_path in path or path in endpoint_path:
            role_name, req = requests[0]
            return [ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="http_smuggling",
                baseline_request=req,
                baseline_role=role_name,
                target_role=None,
                mutated_value="CL.TE",
                mutated_param_name=None,
                mutated_param_location=None,
                description=f"HTTP smuggling: CL.TE probe on {path}",
                experiment_spec=spec,
            )]
    return []


def plan_info_disclosure(
    hyp: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Info disclosure: inject error-triggering values to expose stack traces."""
    endpoint_path = spec.mutation_params.get("endpoint_path", "")
    param_name = spec.mutation_params.get("parameter_name", "")
    payload = spec.mutation_params.get("payload", "'\"<>%00")

    for path, requests in corpus.items():
        if not requests:
            continue
        if not endpoint_path or endpoint_path in path or path in endpoint_path:
            for role_name, req in requests:
                if param_name:
                    value = extract_param_value(req, param_name, "query", path)
                    if value is not None:
                        return [ConcreteExperimentPlan(
                            hypothesis_id=hyp.id,
                            mutation_type="info_disclosure",
                            baseline_request=req,
                            baseline_role=role_name,
                            target_role=None,
                            mutated_value=payload,
                            mutated_param_name=param_name,
                            mutated_param_location="query",
                            description=f"Info disclosure: inject {payload[:20]} into '{param_name}'",
                            experiment_spec=spec,
                        )]
                elif req.query_params:
                    first_param = next(iter(req.query_params))
                    return [ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="info_disclosure",
                        baseline_request=req,
                        baseline_role=role_name,
                        target_role=None,
                        mutated_value=payload,
                        mutated_param_name=first_param,
                        mutated_param_location="query",
                        description=f"Info disclosure: inject {payload[:20]} into '{first_param}'",
                        experiment_spec=spec,
                    )]
    # Fallback: use first corpus entry with a path param or as-is
    for path, requests in corpus.items():
        if requests:
            role_name, req = requests[0]
            return [ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="info_disclosure",
                baseline_request=req,
                baseline_role=role_name,
                target_role=None,
                mutated_value=payload,
                mutated_param_name="",
                mutated_param_location="query",
                description=f"Info disclosure: append error trigger to {path}",
                experiment_spec=spec,
            )]
    return []
