# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import pytest

from hdwp.core.ml.embedders.diff_embedder import DiffEmbedder
from hdwp.core.model.schemas import DiffVerdict, NormalizedResponse, SemanticDiff


def _make_resp(
    status: int = 200,
    body=None,
    timing_ms: float = 100.0,
    headers: dict | None = None,
) -> NormalizedResponse:
    return NormalizedResponse(
        status_code=status,
        body=body,
        headers=headers or {},
        timing_ms=timing_ms,
        content_type=None,
    )


def _make_diff(
    leaked: list[str] | None = None,
    structural: bool = False,
    behavioral: bool = False,
    status_diff: bool = False,
    identity_score: float | None = None,
    suspicious: list[str] | None = None,
) -> SemanticDiff:
    return SemanticDiff(
        exp_a="a",
        exp_b="b",
        structural_difference=structural,
        behavioral_difference=behavioral,
        status_difference=status_diff,
        leaked_fields=leaked or [],
        data_identity_score=identity_score,
        suspicious_fields=suspicious or [],
        verdict=DiffVerdict.INSIGNIFICANT,
        verdict_rationale="",
        body_similarity=1.0,
    )


def test_dimension_is_51():
    assert len(DiffEmbedder().embed(_make_resp(), _make_resp())) == 51


def test_identical_responses_zero_directional_diff():
    r = _make_resp(200, {"id": 1})
    vec = DiffEmbedder().embed(r, r)
    assert all(v == pytest.approx(0.0) for v in vec[:22])


def test_identical_responses_zero_magnitude():
    r = _make_resp(200, {"id": 1})
    vec = DiffEmbedder().embed(r, r)
    assert all(v == pytest.approx(0.0) for v in vec[22:44])


def test_status_change_produces_nonzero_diff():
    baseline = _make_resp(200, {})
    experiment = _make_resp(404, None)
    vec = DiffEmbedder().embed(baseline, experiment)
    assert any(v != 0.0 for v in vec[:22])


def test_structural_diff_bit_set_from_diff_object():
    r = _make_resp()
    diff = _make_diff(structural=True)
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[44] == 1.0


def test_behavioral_diff_bit_set_from_diff_object():
    r = _make_resp()
    diff = _make_diff(behavioral=True)
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[45] == 1.0


def test_status_diff_bit_set_from_diff_object():
    r = _make_resp()
    diff = _make_diff(status_diff=True)
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[46] == 1.0


def test_status_diff_derived_when_no_diff_object():
    baseline = _make_resp(200)
    experiment = _make_resp(403)
    vec = DiffEmbedder().embed(baseline, experiment)
    assert vec[46] == 1.0


def test_no_status_diff_derived_when_same_status():
    r = _make_resp(200)
    vec = DiffEmbedder().embed(r, r)
    assert vec[46] == pytest.approx(0.0)


def test_leaked_fields_normalized():
    r = _make_resp()
    diff = _make_diff(leaked=["field1", "field2", "field3"])
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[47] == pytest.approx(3 / 10.0)


def test_leaked_fields_clamped():
    r = _make_resp()
    diff = _make_diff(leaked=[f"f{i}" for i in range(20)])
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[47] == pytest.approx(1.0)


def test_identity_score_present():
    r = _make_resp()
    diff = _make_diff(identity_score=0.75)
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[48] == pytest.approx(0.75)


def test_identity_score_defaults_to_half_when_none():
    r = _make_resp()
    diff = _make_diff(identity_score=None)
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[48] == pytest.approx(0.5)


def test_identity_score_half_when_no_diff_object():
    r = _make_resp()
    vec = DiffEmbedder().embed(r, r)
    assert vec[48] == pytest.approx(0.5)


def test_suspicious_fields_normalized():
    r = _make_resp()
    diff = _make_diff(suspicious=["token", "password"])
    vec = DiffEmbedder().embed(r, r, diff=diff)
    assert vec[49] == pytest.approx(2 / 5.0)


def test_timing_diff_positive_when_experiment_slower():
    base = _make_resp(timing_ms=100.0)
    exp = _make_resp(timing_ms=200.0)
    vec = DiffEmbedder().embed(base, exp)
    assert vec[50] == pytest.approx(1.0)  # (200-100)/100 = 1.0, clamped


def test_timing_diff_negative_when_experiment_faster():
    base = _make_resp(timing_ms=200.0)
    exp = _make_resp(timing_ms=100.0)
    vec = DiffEmbedder().embed(base, exp)
    assert vec[50] == pytest.approx(-0.5)  # (100-200)/200 = -0.5


def test_timing_diff_clamped_positive():
    base = _make_resp(timing_ms=100.0)
    exp = _make_resp(timing_ms=99999.0)
    vec = DiffEmbedder().embed(base, exp)
    assert vec[50] == pytest.approx(1.0)


def test_timing_diff_clamped_negative():
    base = _make_resp(timing_ms=1000.0)
    exp = _make_resp(timing_ms=0.0)
    vec = DiffEmbedder().embed(base, exp)
    assert vec[50] == pytest.approx(-1.0)


def test_all_structural_bits_zero_with_no_diff():
    r = _make_resp()
    vec = DiffEmbedder().embed(r, r)
    assert vec[44] == 0.0  # structural
    assert vec[45] == 0.0  # behavioral
    assert vec[47] == 0.0  # leaked_fields
    assert vec[49] == 0.0  # suspicious_fields
