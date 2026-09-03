# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ViolationOracle: mutation-type-aware vulnerability verdict.

The semantic meaning of a "violation" differs by mutation type.
Les assesseurs sont enregistres dans MutationRegistry.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from hdwp.core.model.schemas import DiffVerdict, ExperimentResult, SemanticDiff


class ViolationVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    AMBIGUOUS = "AMBIGUOUS"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass
class ViolationAssessment:
    verdict: ViolationVerdict
    rationale: str
    confidence_hint: float


def assess_violation(
    mutation_type: str,
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    """Delegue au MutationRegistry si disponible, sinon fallback generic."""
    from hdwp.core.mutation_registry import assess

    result = assess(mutation_type, baseline, experiment, diff)
    if isinstance(result, ViolationAssessment):
        return result
    return _assess_generic(diff)


# ── Assesseurs individuels (importables par mutation_registry) ──────────────


def _assess_identity_swap(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    exp_status = experiment.response_received.status_code
    base_status = baseline.response_received.status_code

    if exp_status in (401, 403):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Access correctly denied ({exp_status}) for different identity",
            confidence_hint=0.9,
        )

    if base_status < 300 and exp_status < 300:
        if diff.body_similarity >= 0.7 or not diff.structural_difference:
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale=(
                    f"Identity swap succeeded: attacker receives same data as owner "
                    f"(similarity={diff.body_similarity:.2f}, status={exp_status})"
                ),
                confidence_hint=0.9 if diff.body_similarity >= 0.9 else 0.7,
            )
        return ViolationAssessment(
            verdict=ViolationVerdict.AMBIGUOUS,
            rationale=f"Identity swap returned {exp_status} but response differs structurally",
            confidence_hint=0.4,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.INSUFFICIENT,
        rationale=f"Inconclusive: baseline={base_status}, experiment={exp_status}",
        confidence_hint=0.0,
    )


def _assess_object_ref_change(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    exp_status = experiment.response_received.status_code

    if exp_status in (401, 403, 404):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Ownership enforced: returned {exp_status} for foreign object",
            confidence_hint=0.9,
        )

    if exp_status < 300:
        exp_body = experiment.response_received.body
        has_data = isinstance(exp_body, dict) and len(exp_body) > 0
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=(
                f"Foreign object accessible: returned {exp_status} with "
                f"{'data' if has_data else 'empty body'}"
            ),
            confidence_hint=0.9 if has_data else 0.6,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS,
        rationale=f"Unexpected status {exp_status} -- needs further analysis",
        confidence_hint=0.3,
    )


def _assess_privilege_escalation(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    exp_status = experiment.response_received.status_code

    if exp_status in (401, 403):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Access correctly denied ({exp_status}) for unauthorized role",
            confidence_hint=0.95,
        )

    if exp_status < 300:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=f"Privilege escalation succeeded: endpoint returned {exp_status}",
            confidence_hint=0.95,
        )

    if 300 <= exp_status < 400:
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Redirect ({exp_status}) suggests auth enforcement",
            confidence_hint=0.7,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS,
        rationale=f"Status {exp_status} -- inconclusive",
        confidence_hint=0.2,
    )


def _assess_field_injection(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    """Delegate to InjectionOracle using the payload_type from mutation_params."""
    from hdwp.core.oracle.injection_oracle import assess_injection

    params = experiment.experiment_spec.mutation_params
    payload_type = params.get("payload_type", "sqli")
    payload = params.get("payload", "")
    expected_result = params.get("expected_result", "")
    extra_field = params.get("extra_field", "")
    return assess_injection(payload_type, payload, experiment, expected_result, extra_field)


def _assess_jwt_manipulation(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    """JWT: token forge accepte (2xx) = vulnerabilite; rejete (401/403) = protection ok."""
    exp_status = experiment.response_received.status_code
    attack = experiment.experiment_spec.mutation_params.get("jwt_attack", "unknown")

    if exp_status in (401, 403):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"JWT {attack}: token manipule rejete ({exp_status})",
            confidence_hint=0.9,
        )
    if exp_status < 300:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=f"JWT {attack}: token manipule accepte ({exp_status}) -- validation JWT defaillante",
            confidence_hint=0.95,
        )
    return ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS,
        rationale=f"JWT {attack}: status inattendu {exp_status}",
        confidence_hint=0.3,
    )


def _assess_cors(
    baseline: ExperimentResult,
    experiment: ExperimentResult,
    diff: SemanticDiff,
) -> ViolationAssessment:
    """CORS: verifie si Access-Control-Allow-Origin reflete l'origine malveillante.

    * ACAO: * est une vulnérabilité UNIQUEMENT sur endpoints avec credentials.
    * ACAO reflété est une vulnérabilité UNIQUEMENT si l'endpoint original refuse CORS.
    """
    headers = {k.lower(): v for k, v in experiment.response_received.headers.items()}
    baseline_headers = {k.lower(): v for k, v in baseline.response_received.headers.items()}
    acao = headers.get("access-control-allow-origin", "")
    baseline_acao = baseline_headers.get("access-control-allow-origin", "")
    evil_origin = experiment.experiment_spec.mutation_params.get("evil_origin", "")

    # If endpoint returns ACAO: *, it's only a vulnerability if credentials/auth are involved
    if acao == "*":
        if baseline.response_received.headers.get("set-cookie") or "authorization" in {k.lower() for k in baseline.response_received.headers}:
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale="Access-Control-Allow-Origin: * sur endpoint authentifié",
                confidence_hint=0.9,
            )
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="Access-Control-Allow-Origin: * sur API publique (pas d'auth)",
            confidence_hint=0.7,
        )

    # ACAO reflection is only a vulnerability if baseline doesn't have CORS enabled
    if evil_origin and acao == evil_origin:
        if not baseline_acao:
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale="CORS reflection vulnérable : origine malveillante acceptée",
                confidence_hint=0.95,
            )
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="Endpoint a une politique CORS de base — reflection non exploitable",
            confidence_hint=0.6,
        )

    if not acao:
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="Aucun header CORS -- comportement correct",
            confidence_hint=0.8,
        )
    return ViolationAssessment(
        verdict=ViolationVerdict.REFUTED,
        rationale=f"CORS restreint : {acao}",
        confidence_hint=0.85,
    )


def _assess_generic(diff: SemanticDiff) -> ViolationAssessment:
    match diff.verdict:
        case DiffVerdict.SIGNIFICANT:
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale=f"Significant diff: {diff.verdict_rationale}",
                confidence_hint=0.7,
            )
        case DiffVerdict.AMBIGUOUS:
            return ViolationAssessment(
                verdict=ViolationVerdict.AMBIGUOUS,
                rationale=diff.verdict_rationale,
                confidence_hint=0.4,
            )
        case _:
            return ViolationAssessment(
                verdict=ViolationVerdict.REFUTED,
                rationale="No significant difference observed",
                confidence_hint=0.6,
            )
