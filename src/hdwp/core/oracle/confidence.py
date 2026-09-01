# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Operational definitions for the 5-dimensional confidence model.

observation_quality:
    Reflects how well-observed the related endpoints were before the experiment.
    Formula: min(1.0, log(1 + n_obs_for_endpoint) / log(6))
    Saturates at 5 observations.

behavioral_specificity:
    Reflects how specific the observed diff is to the property being violated.
"""
from __future__ import annotations

import math

from hdwp.core.model.schemas import ConfidenceScore, ExperimentResult, SemanticDiff
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
) -> ConfidenceScore:
    oracle_strength = assessment.confidence_hint
    coverage = math.log(1 + n_experiments_done) / math.log(
        1 + max(n_experiments_required, 1)
    )
    overall = (
        WEIGHTS["oracle_strength"] * oracle_strength
        + WEIGHTS["reproducibility"] * reproducibility
        + WEIGHTS["observation_quality"] * observation_quality
        + WEIGHTS["behavioral_specificity"] * behavioral_specificity
        + WEIGHTS["experiment_coverage"] * coverage
    )
    return ConfidenceScore(
        oracle_strength=round(oracle_strength, 4),
        reproducibility=round(reproducibility, 4),
        observation_quality=round(observation_quality, 4),
        behavioral_specificity=round(behavioral_specificity, 4),
        experiment_coverage=round(coverage, 4),
        overall=round(overall, 4),
    )
