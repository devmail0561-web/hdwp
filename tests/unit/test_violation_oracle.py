# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    DiffVerdict,
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    SemanticDiff,
    generate_id,
)
from hdwp.core.oracle.violation_oracle import ViolationVerdict, assess_violation


def _make_result(status: int, body: object = None) -> ExperimentResult:
    spec = ExperimentSpec(
        mutation_type="identity_swap",
        base_request=NormalizedRequest(method="GET", url="http://test/api/users/1"),
        mutation_params={},
    )
    return ExperimentResult(
        id=generate_id("EXP"),
        hypothesis_id="HYP-test",
        experiment_spec=spec,
        request_sent=NormalizedRequest(method="GET", url="http://test/api/users/1"),
        response_received=NormalizedResponse(status_code=status, body=body),
        timestamp="2026-09-01T00:00:00Z",
    )


def _make_diff(
    verdict: DiffVerdict = DiffVerdict.INSIGNIFICANT,
    body_similarity: float = 1.0,
    structural: bool = False,
    status_diff: bool = False,
) -> SemanticDiff:
    return SemanticDiff(
        id=generate_id("DIFF"),
        exp_a="EXP-a",
        exp_b="EXP-b",
        structural_difference=structural,
        behavioral_difference=False,
        leaked_fields=[],
        status_difference=status_diff,
        body_similarity=body_similarity,
        verdict=verdict,
        verdict_rationale="test",
    )


# ── identity_swap ──────────────────────────────────────────────────────────

def test_identity_swap_both_200_high_similarity_confirmed() -> None:
    baseline = _make_result(200, {"id": 1, "name": "alice"})
    experiment = _make_result(200, {"id": 1, "name": "alice"})
    diff = _make_diff(body_similarity=1.0)
    assessment = assess_violation("identity_swap", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.CONFIRMED
    assert assessment.confidence_hint >= 0.7


def test_identity_swap_experiment_403_refuted() -> None:
    baseline = _make_result(200, {"id": 1})
    experiment = _make_result(403)
    diff = _make_diff(status_diff=True, verdict=DiffVerdict.SIGNIFICANT)
    assessment = assess_violation("identity_swap", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED


def test_identity_swap_experiment_401_refuted() -> None:
    baseline = _make_result(200, {"id": 1})
    experiment = _make_result(401)
    diff = _make_diff(status_diff=True)
    assessment = assess_violation("identity_swap", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED


def test_identity_swap_both_200_structurally_different_ambiguous() -> None:
    baseline = _make_result(200, {"id": 1, "name": "alice"})
    experiment = _make_result(200, {"user_id": 2, "username": "bob", "role": "admin"})
    diff = _make_diff(body_similarity=0.0, structural=True, verdict=DiffVerdict.SIGNIFICANT)
    assessment = assess_violation("identity_swap", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.AMBIGUOUS


# ── object_ref_change ──────────────────────────────────────────────────────

def test_object_ref_change_200_with_data_confirmed() -> None:
    baseline = _make_result(200, {"id": 1, "name": "alice"})
    experiment = _make_result(200, {"id": 2, "name": "bob"})
    diff = _make_diff(body_similarity=0.5)
    assessment = assess_violation("object_ref_change", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.CONFIRMED
    assert assessment.confidence_hint >= 0.8


def test_object_ref_change_403_refuted() -> None:
    baseline = _make_result(200, {"id": 1})
    experiment = _make_result(403)
    diff = _make_diff()
    assessment = assess_violation("object_ref_change", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED


def test_object_ref_change_404_refuted() -> None:
    baseline = _make_result(200, {"id": 1})
    experiment = _make_result(404)
    diff = _make_diff()
    assessment = assess_violation("object_ref_change", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED


# ── privilege_escalation ───────────────────────────────────────────────────

def test_privilege_escalation_200_confirmed() -> None:
    baseline = _make_result(200, {"users": []})
    experiment = _make_result(200, {"users": []})
    diff = _make_diff()
    assessment = assess_violation("privilege_escalation", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.CONFIRMED
    assert assessment.confidence_hint >= 0.9


def test_privilege_escalation_403_refuted() -> None:
    baseline = _make_result(200, {"users": []})
    experiment = _make_result(403)
    diff = _make_diff(status_diff=True)
    assessment = assess_violation("privilege_escalation", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED


def test_privilege_escalation_302_refuted() -> None:
    baseline = _make_result(200)
    experiment = _make_result(302)
    diff = _make_diff(status_diff=True)
    assessment = assess_violation("privilege_escalation", baseline, experiment, diff)
    assert assessment.verdict == ViolationVerdict.REFUTED
