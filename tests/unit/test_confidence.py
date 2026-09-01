# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math

from hdwp.core.model.schemas import (
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    SemanticDiff,
    DiffVerdict,
    generate_id,
)
from hdwp.core.oracle.confidence import (
    compute_behavioral_specificity,
    compute_confidence,
    compute_observation_quality,
)
from hdwp.core.oracle.violation_oracle import ViolationAssessment, ViolationVerdict


def _make_result(status: int, body: object = None) -> ExperimentResult:
    spec = ExperimentSpec(
        mutation_type="identity_swap",
        base_request=NormalizedRequest(method="GET", url="http://test/"),
        mutation_params={},
    )
    return ExperimentResult(
        id=generate_id("EXP"),
        hypothesis_id="HYP-test",
        experiment_spec=spec,
        request_sent=NormalizedRequest(method="GET", url="http://test/"),
        response_received=NormalizedResponse(status_code=status, body=body),
        timestamp="2026-09-01T00:00:00Z",
    )


def _make_diff(similarity: float = 1.0, verdict: DiffVerdict = DiffVerdict.INSIGNIFICANT) -> SemanticDiff:
    return SemanticDiff(
        id=generate_id("DIFF"),
        exp_a="EXP-a", exp_b="EXP-b",
        structural_difference=False, behavioral_difference=False,
        leaked_fields=[], status_difference=False,
        body_similarity=similarity, verdict=verdict, verdict_rationale="test",
    )


def _confirmed(hint: float = 0.9) -> ViolationAssessment:
    return ViolationAssessment(
        verdict=ViolationVerdict.CONFIRMED,
        rationale="test",
        confidence_hint=hint,
    )


# ── observation_quality ────────────────────────────────────────────────────

def test_observation_quality_zero_obs() -> None:
    assert compute_observation_quality(0) == 0.0


def test_observation_quality_saturates_at_five() -> None:
    q = compute_observation_quality(5)
    assert abs(q - 1.0) < 0.01


def test_observation_quality_increases_monotonically() -> None:
    values = [compute_observation_quality(n) for n in range(6)]
    assert values == sorted(values)


def test_observation_quality_one_obs() -> None:
    q = compute_observation_quality(1)
    assert 0.3 < q < 0.5


# ── behavioral_specificity ─────────────────────────────────────────────────

def test_behavioral_specificity_identity_swap_confirmed_high_similarity() -> None:
    diff = _make_diff(similarity=0.95)
    exp = _make_result(200, {"id": 1, "name": "alice"})
    assessment = _confirmed()
    score = compute_behavioral_specificity("identity_swap", diff, exp, assessment)
    assert score >= 0.9


def test_behavioral_specificity_object_ref_with_data() -> None:
    diff = _make_diff()
    exp = _make_result(200, {"id": 2, "name": "bob"})
    assessment = _confirmed()
    score = compute_behavioral_specificity("object_ref_change", diff, exp, assessment)
    assert score == 0.9


def test_behavioral_specificity_privilege_escalation_confirmed() -> None:
    diff = _make_diff()
    exp = _make_result(200)
    assessment = _confirmed()
    score = compute_behavioral_specificity("privilege_escalation", diff, exp, assessment)
    assert score == 0.95


def test_behavioral_specificity_ambiguous_is_moderate() -> None:
    diff = _make_diff()
    exp = _make_result(200)
    assessment = ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS, rationale="test", confidence_hint=0.4
    )
    score = compute_behavioral_specificity("identity_swap", diff, exp, assessment)
    assert score == 0.4


def test_behavioral_specificity_refuted_is_low() -> None:
    diff = _make_diff()
    exp = _make_result(403)
    assessment = ViolationAssessment(
        verdict=ViolationVerdict.REFUTED, rationale="test", confidence_hint=0.9
    )
    score = compute_behavioral_specificity("identity_swap", diff, exp, assessment)
    assert score == 0.1


# ── compute_confidence ─────────────────────────────────────────────────────

def test_confidence_overall_in_range() -> None:
    assessment = _confirmed(0.9)
    score = compute_confidence(
        assessment=assessment,
        reproducibility=0.8,
        observation_quality=0.7,
        behavioral_specificity=0.9,
        n_experiments_done=2,
        n_experiments_required=2,
    )
    assert 0.0 <= score.overall <= 1.0


def test_confidence_high_when_all_dimensions_high() -> None:
    assessment = _confirmed(0.95)
    score = compute_confidence(
        assessment=assessment,
        reproducibility=1.0,
        observation_quality=1.0,
        behavioral_specificity=1.0,
        n_experiments_done=5,
        n_experiments_required=2,
    )
    assert score.overall >= 0.85


def test_confidence_low_when_refuted() -> None:
    assessment = ViolationAssessment(
        verdict=ViolationVerdict.REFUTED, rationale="held", confidence_hint=0.05
    )
    score = compute_confidence(
        assessment=assessment,
        reproducibility=0.1,
        observation_quality=0.2,
        behavioral_specificity=0.1,
        n_experiments_done=1,
        n_experiments_required=3,
    )
    assert score.overall < 0.4


def test_confidence_dimensions_stored_correctly() -> None:
    assessment = _confirmed(0.8)
    score = compute_confidence(
        assessment=assessment,
        reproducibility=0.6,
        observation_quality=0.5,
        behavioral_specificity=0.7,
        n_experiments_done=1,
        n_experiments_required=1,
    )
    assert score.oracle_strength == 0.8
    assert score.reproducibility == 0.6
    assert score.observation_quality == 0.5
    assert score.behavioral_specificity == 0.7
