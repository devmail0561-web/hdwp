# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
StrategyPivot : génère des hypothèses alternatives quand une classe d'attaque
est systématiquement refutée sur le même endpoint/paramètre.

Contrairement au bandit Thompson Sampling (qui baisse la priorité d'un arm),
StrategyPivot génère activement des hypothèses sur un vecteur différent.

Pilotage par tech_stack :
  - SQLi → NoSQLi uniquement si db:mongodb/dynamodb/couchdb détecté
  - XSS → SSTI uniquement si framework:jinja2/twig/smarty détecté
  - Pivots génériques (object_ref_change → identity_swap) toujours actifs

Cycle guard : _seen_keys de HypothesisEngine bloque les re-pivots.
Confidence threshold : si avg_confidence ≥ 0.80 sur les refutations, le paramètre
est clairement sûr — pas de pivot.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, Hypothesis

from hdwp.core.model.schemas import ExperimentSpec, NormalizedRequest

PIVOT_THRESHOLD = 3
PIVOT_MAX_AVG_CONFIDENCE = 0.80

# (mutation_type:payload_type) → [(alt_mutation_type, required_tech_tags)]
# required_tech_tags vide = pivot toujours valide
_PIVOT_MAP: dict[str, list[tuple[str, set[str]]]] = {
    "field_injection:sqli": [
        ("field_injection:nosqli",  {"db:mongodb", "db:dynamodb", "db:couchdb"}),
        ("field_injection:sqli_waf",    set()),  # retry avec bypass WAF
    ],
    "field_injection:xss": [
        ("field_injection:ssti",    {"framework:jinja2", "framework:twig", "framework:smarty"}),
    ],
    "field_injection:nosqli": [
        ("field_injection:sqli",    set()),
    ],
    "object_ref_change": [
        ("identity_swap",           set()),
    ],
    "privilege_escalation": [
        ("method_override",         set()),
    ],
    "jwt": [
        ("identity_swap",           set()),
    ],
    "identity_swap": [
        ("object_ref_change",       set()),
    ],
}

# Payloads alternatifs pour les pivots WAF bypass SQLi
_SQLI_WAF_BYPASS = [
    "1' OR/**/ '1'='1",
    "1%27+OR+%271%27%3D%271",
    "1' OR 0x313D31--",
    "1';EXEC(CHAR(115)+CHAR(101)+CHAR(108))--",
]


def endpoint_hash(endpoint_path: str) -> str:
    """Hash du pattern d'URL — normalise les IDs variables."""
    import re
    # Remplacer les segments numériques/UUIDs par {id}
    normalized = re.sub(r'/\d+', '/{id}', endpoint_path)
    normalized = re.sub(r'/[0-9a-f-]{36}', '/{uuid}', normalized)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def should_pivot(confidences: list[float]) -> bool:
    """Vrai si le seuil est atteint ET que les refutations ne sont pas de haute confiance."""
    if len(confidences) < PIVOT_THRESHOLD:
        return False
    avg = sum(confidences) / len(confidences)
    # Refutations haute confiance = paramètre clairement sûr, pas de pivot
    return avg < PIVOT_MAX_AVG_CONFIDENCE


def get_pivot_mutations(
    mutation_type: str,
    payload_type: str,
    tech_stack: set[str],
) -> list[str]:
    """Retourne les types de mutation alternatifs valides pour cette tech_stack."""
    key = f"{mutation_type}:{payload_type}" if payload_type else mutation_type
    entries = _PIVOT_MAP.get(key, _PIVOT_MAP.get(mutation_type, []))
    result = []
    for alt_mutation, required_tags in entries:
        if not required_tags or required_tags & tech_stack:
            result.append(alt_mutation)
    return result


def generate_pivot_hypotheses(
    endpoint: str,
    mutation_type: str,
    proof: dict[str, Any],
    model: ApplicationModelData,
) -> list[Hypothesis]:
    """Génère des hypothèses alternatives depuis les infos du finding refuté."""
    from hdwp.core.model.schemas import Hypothesis, generate_id

    payload_type = proof.get("payload_type", "")
    tech_stack = set(model.tech_stack)
    pivot_mutations = get_pivot_mutations(mutation_type, payload_type, tech_stack)

    if not pivot_mutations:
        return []

    # Récupérer les informations du paramètre depuis le proof
    winning_req = proof.get("winning_request", {}) if isinstance(proof.get("winning_request"), dict) else {}
    param_name = proof.get("param_name") or ""
    if not param_name and winning_req:
        qp = winning_req.get("query_params", {})
        if isinstance(qp, dict) and qp:
            param_name = next(iter(qp.keys()))

    hypotheses = []
    for alt_mutation in pivot_mutations:
        pivot_payload_type = alt_mutation.split(":")[-1] if ":" in alt_mutation else ""
        base_mutation = alt_mutation.split(":")[0] if ":" in alt_mutation else alt_mutation

        payloads: list[str] = []
        if pivot_payload_type == "nosqli":
            payloads = ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}']
        elif pivot_payload_type == "ssti":
            payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
        elif pivot_payload_type == "sqli_waf":
            payloads = _SQLI_WAF_BYPASS
        else:
            payloads = [""]  # pivot structurel (ex: object_ref_change → identity_swap)

        for payload in payloads[:3]:
            mutation_params: dict[str, Any] = {
                "endpoint_path": endpoint,
                "_pivot_from": mutation_type,
            }
            if param_name:
                mutation_params["parameter_name"] = param_name
                mutation_params["parameter_location"] = "query"
            if payload:
                mutation_params["payload"] = payload
                mutation_params["payload_type"] = pivot_payload_type

            hyp = Hypothesis(
                id=generate_id("HYP"),
                source_plugin="strategy_pivot",
                property_id="",
                statement=(
                    f"[PIVOT] {endpoint} — {mutation_type} refuté → essayer {base_mutation}"
                    + (f" ({pivot_payload_type})" if pivot_payload_type else "")
                ),
                priority="MEDIUM",
                priority_rationale=f"Pivot stratégique : {mutation_type} refuté {PIVOT_THRESHOLD}× avec confiance faible",
                required_experiments=[ExperimentSpec(
                    mutation_type=base_mutation,
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params=mutation_params,
                    description=f"Pivot {mutation_type}→{base_mutation}",
                )],
            )
            hypotheses.append(hyp)

    return hypotheses
