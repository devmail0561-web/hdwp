# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math

from hdwp.core.oracle.confidence import (
    ConfidenceModelV2,
    V2_DIMENSIONS,
    V2_DEFAULT_WEIGHTS,
    V2_DEFAULT_BIAS,
    _sigmoid,
    ConfidenceScore,
    compute_confidence,
    CONFIRMED_THRESHOLD,
)
from hdwp.core.oracle.violation_oracle import ViolationAssessment, ViolationVerdict


def _make_v1_score(
    oracle_strength: float = 0.0,
    reproducibility: float = 0.0,
    observation_quality: float = 0.0,
    behavioral_specificity: float = 0.0,
    experiment_coverage: float = 0.0,
    overall: float = 0.0,
) -> ConfidenceScore:
    return ConfidenceScore(
        oracle_strength=oracle_strength,
        reproducibility=reproducibility,
        observation_quality=observation_quality,
        behavioral_specificity=behavioral_specificity,
        experiment_coverage=experiment_coverage,
        overall=overall,
    )


def _make_model(
    weights: dict[str, float] | None = None,
    bias: float = V2_DEFAULT_BIAS,
) -> ConfidenceModelV2:
    if weights is not None:
        return ConfidenceModelV2(weights=weights, bias=bias)
    return ConfidenceModelV2(bias=bias)


def _make_assessment(
    verdict: ViolationVerdict = ViolationVerdict.CONFIRMED,
    hint: float = 0.9,
) -> ViolationAssessment:
    return ViolationAssessment(
        verdict=verdict,
        rationale="test",
        confidence_hint=hint,
    )


def test_sigmoid_zero_returns_half():
    assert abs(_sigmoid(0) - 0.5) < 1e-9


def test_sigmoid_extremes_saturate_correctly():
    assert _sigmoid(50.0) > 0.999
    assert _sigmoid(-50.0) < 0.001


def test_sigmoid_negative_overflow_no_error():
    result = _sigmoid(-1000.0)
    assert 0.0 <= result <= 1.0


def test_predict_returns_float_in_unit_interval():
    model = _make_model()
    features = {"oracle_strength": 0.5, "reproducibility": 0.8}
    p = model.predict(features)
    assert isinstance(p, float)
    assert 0.0 <= p <= 1.0


def test_predict_all_zeros_returns_sigmoid_of_bias():
    model = _make_model()
    p = model.predict({})
    expected = round(_sigmoid(V2_DEFAULT_BIAS), 4)
    assert p == expected
    assert abs(p - 0.018) < 0.002


def test_predict_all_ones_higher_than_all_zeros():
    model = _make_model()
    p_zero = model.predict({})
    p_ones = model.predict({dim: 1.0 for dim in V2_DIMENSIONS})
    assert p_ones > p_zero
    assert p_ones > 0.5


def test_predict_missing_features_treated_as_zero():
    model = _make_model()
    partial = {"oracle_strength": 0.5}
    full = {"oracle_strength": 0.5}
    for dim in V2_DIMENSIONS:
        if dim != "oracle_strength":
            full[dim] = 0.0
    assert model.predict(partial) == model.predict(full)


def test_compute_v2_returns_float_in_unit_interval():
    model = _make_model()
    v1 = _make_v1_score(
        oracle_strength=0.8,
        reproducibility=0.7,
        observation_quality=0.6,
        behavioral_specificity=0.5,
        experiment_coverage=0.4,
    )
    score = model.compute_v2(v1, temporal_signal=0.3, crossrole_signal=0.2)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_compute_v2_high_invariant_violated_increases_score():
    model = _make_model()
    v1 = _make_v1_score(oracle_strength=0.5, reproducibility=0.5)
    low = model.compute_v2(v1, invariant_violated=0.0)
    high = model.compute_v2(v1, invariant_violated=1.0)
    assert high > low
    assert high - low > 0.05


def test_compute_v2_high_crossrole_signal_increases_score():
    model = _make_model()
    v1 = _make_v1_score(oracle_strength=0.5, reproducibility=0.5)
    low = model.compute_v2(v1, crossrole_signal=0.0)
    high = model.compute_v2(v1, crossrole_signal=1.0)
    assert high > low


def test_update_weights_applies_known_ignores_unknown():
    model = _make_model()
    original = model.weights["oracle_strength"]
    before = dict(model.weights)
    model.update_weights({"oracle_strength": 99.0, "nonexistent_dimension": 42.0})
    assert model.weights["oracle_strength"] == 99.0
    assert model.weights["oracle_strength"] != original
    assert "nonexistent_dimension" not in model.weights
    for dim in V2_DIMENSIONS:
        if dim != "oracle_strength":
            assert model.weights[dim] == before[dim]


def test_v2_dimensions_has_exactly_ten_elements():
    assert len(V2_DIMENSIONS) == 10


def test_fallback_all_v2_signals_zero_close_to_v1_range():
    assessment = _make_assessment(hint=0.8)
    v1 = compute_confidence(
        assessment=assessment,
        reproducibility=0.7,
        observation_quality=0.6,
        behavioral_specificity=0.5,
        n_experiments_done=3,
        n_experiments_required=5,
    )
    model = _make_model()
    v2_score = model.compute_v2(v1)
    assert 0.0 <= v2_score <= 1.0
    assert v2_score < 0.9
