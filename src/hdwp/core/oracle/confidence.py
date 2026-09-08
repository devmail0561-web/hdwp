# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Confidence model — V1 (5D linear) + V2 (10D logistic).

V1 is preserved for backward compatibility and as fallback.
V2 adds 5 dimensions: temporal_signal, crossrole_signal, invariant_violated,
waf_bypass_success, causal_depth. ADR-NEW-004: weights only updated after
manual validation — no unsupervised auto-update.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from hdwp.core.model.schemas import ConfidenceScore, ExperimentResult, SemanticDiff, SignalContribution
from hdwp.core.oracle.violation_oracle import ViolationAssessment, ViolationVerdict

WEIGHTS = {
    "oracle_strength": 0.25,
    "reproducibility": 0.30,
    "observation_quality": 0.15,
    "behavioral_specificity": 0.15,
    "experiment_coverage": 0.15,
}

CONFIRMED_THRESHOLD = 0.85


def compute_observation_quality(n_observations_for_endpoint: int) -> float:
    """Saturates at 5 observations."""
    return min(1.0, math.log(1 + n_observations_for_endpoint) / math.log(6))


# ── Individual specificity functions (importable par mutation_registry) ─────


def _compute_behavioral_specificity_identity_swap(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        return min(1.0, diff.body_similarity + 0.1 * len(diff.leaked_fields))
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


def _compute_behavioral_specificity_object_ref(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        has_data = (
            isinstance(experiment.response_received.body, dict)
            and len(experiment.response_received.body) > 0
        )
        return 0.9 if has_data else 0.5
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


def _compute_behavioral_specificity_privilege_escalation(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        return 0.95 if experiment.response_received.status_code < 300 else 0.0
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


def _compute_behavioral_specificity_field_injection(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        return 0.6 if diff.verdict.value == "SIGNIFICANT" else 0.3
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


def _compute_behavioral_specificity_jwt(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        return 0.95 if experiment.response_received.status_code < 300 else 0.0
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


def _compute_behavioral_specificity_cors(
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    if assessment.verdict == ViolationVerdict.CONFIRMED:
        return 0.9
    if assessment.verdict == ViolationVerdict.AMBIGUOUS:
        return 0.4
    return 0.1


# ── Public API ──────────────────────────────────────────────────────────────


def compute_behavioral_specificity(
    mutation_type: str,
    diff: SemanticDiff,
    experiment: ExperimentResult,
    assessment: ViolationAssessment,
) -> float:
    """Delegue au MutationRegistry si disponible, sinon fallback."""
    from hdwp.core.mutation_registry import specificity

    return specificity(mutation_type, diff, experiment, assessment)


def compute_confidence(
    assessment: ViolationAssessment,
    reproducibility: float,
    observation_quality: float,
    behavioral_specificity: float,
    n_experiments_done: int,
    n_experiments_required: int,
    weights: dict[str, float] | None = None,
) -> ConfidenceScore:
    w = weights if weights is not None else WEIGHTS
    oracle_strength = assessment.confidence_hint
    coverage = math.log(1 + n_experiments_done) / math.log(
        1 + max(n_experiments_required, 1)
    )
    overall = (
        w.get("oracle_strength", WEIGHTS["oracle_strength"]) * oracle_strength
        + w.get("reproducibility", WEIGHTS["reproducibility"]) * reproducibility
        + w.get("observation_quality", WEIGHTS["observation_quality"]) * observation_quality
        + w.get("behavioral_specificity", WEIGHTS["behavioral_specificity"]) * behavioral_specificity
        + w.get("experiment_coverage", WEIGHTS["experiment_coverage"]) * coverage
    )
    return ConfidenceScore(
        oracle_strength=round(oracle_strength, 4),
        reproducibility=round(reproducibility, 4),
        observation_quality=round(observation_quality, 4),
        behavioral_specificity=round(behavioral_specificity, 4),
        experiment_coverage=round(coverage, 4),
        overall=round(overall, 4),
    )


# ── V2 Confidence Model (10D logistic) ──────────────────────────────────────

V2_DIMENSIONS = [
    "oracle_strength",
    "reproducibility",
    "observation_quality",
    "behavioral_specificity",
    "experiment_coverage",
    "temporal_signal",
    "crossrole_signal",
    "invariant_violated",
    "waf_bypass_success",
    "causal_depth",
]

V2_DEFAULT_WEIGHTS = {
    "oracle_strength": 1.8,
    "reproducibility": 2.2,
    "observation_quality": 0.8,
    "behavioral_specificity": 1.0,
    "experiment_coverage": 0.7,
    "temporal_signal": 1.5,
    "crossrole_signal": 1.8,
    "invariant_violated": 2.5,
    "waf_bypass_success": 0.6,
    "causal_depth": 1.2,
}

V2_DEFAULT_BIAS = -4.0

_DIMENSION_LABELS = {
    "oracle_strength": "Force du verdict oracle",
    "reproducibility": "Reproductibilité",
    "observation_quality": "Qualité des observations",
    "behavioral_specificity": "Spécificité comportementale",
    "experiment_coverage": "Couverture expérimentale",
    "temporal_signal": "Anomalie temporelle détectée",
    "crossrole_signal": "Différence cross-rôle confirmée",
    "invariant_violated": "Invariant de sécurité violé",
    "waf_bypass_success": "Contournement WAF réussi",
    "causal_depth": "Profondeur de causalité (replays)",
}


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


@dataclass
class ConfidenceModelV2:
    weights: dict[str, float] = field(default_factory=lambda: dict(V2_DEFAULT_WEIGHTS))
    bias: float = V2_DEFAULT_BIAS

    def predict(self, features: dict[str, float]) -> float:
        z = self.bias
        for dim in V2_DIMENSIONS:
            z += self.weights.get(dim, 0.0) * features.get(dim, 0.0)
        return round(_sigmoid(z), 4)

    def compute_v2(
        self,
        v1_score: ConfidenceScore,
        temporal_signal: float = 0.0,
        crossrole_signal: float = 0.0,
        invariant_violated: float = 0.0,
        waf_bypass_success: float = 0.0,
        causal_depth: float = 0.0,
    ) -> float:
        features = {
            "oracle_strength": v1_score.oracle_strength,
            "reproducibility": v1_score.reproducibility,
            "observation_quality": v1_score.observation_quality,
            "behavioral_specificity": v1_score.behavioral_specificity,
            "experiment_coverage": v1_score.experiment_coverage,
            "temporal_signal": temporal_signal,
            "crossrole_signal": crossrole_signal,
            "invariant_violated": invariant_violated,
            "waf_bypass_success": waf_bypass_success,
            "causal_depth": causal_depth,
        }
        return self.predict(features)

    def explain(self, features: dict[str, float]) -> list[SignalContribution]:
        contributions = []
        for dim in V2_DIMENSIONS:
            raw = features.get(dim, 0.0)
            w = self.weights.get(dim, 0.0)
            contributions.append(SignalContribution(
                dimension=dim,
                raw_value=round(raw, 4),
                weight=round(w, 4),
                contribution=round(w * raw, 4),
                label=_DIMENSION_LABELS.get(dim, dim),
            ))
        contributions.sort(key=lambda c: abs(c.contribution), reverse=True)
        return contributions

    def update_weights(self, new_weights: dict[str, float]) -> None:
        for dim in V2_DIMENSIONS:
            if dim in new_weights:
                self.weights[dim] = new_weights[dim]
