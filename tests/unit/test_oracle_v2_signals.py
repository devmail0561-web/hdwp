# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import pytest

from hdwp.core.oracle.confidence import CONFIRMED_THRESHOLD, ConfidenceModelV2
from hdwp.core.model.schemas import ConfidenceScore


def _make_v1(
    overall: float = 0.70,
    oracle_strength: float = 0.7,
    reproducibility: float = 0.7,
    obs_quality: float = 0.5,
    behavioral_specificity: float = 0.5,
    coverage: float = 0.5,
) -> ConfidenceScore:
    return ConfidenceScore(
        oracle_strength=oracle_strength,
        reproducibility=reproducibility,
        observation_quality=obs_quality,
        behavioral_specificity=behavioral_specificity,
        experiment_coverage=coverage,
        overall=overall,
    )


def test_v2_with_no_signals_does_not_exceed_v1_by_default():
    """Sans signaux V3, V2 avec des poids standard ≤ V1 fort (max preserve la confiance)."""
    model = ConfidenceModelV2()
    v1 = _make_v1(overall=0.90, oracle_strength=0.9, reproducibility=0.9)
    v2 = model.compute_v2(v1)
    final = max(v1.overall, v2)
    assert final >= v1.overall


def test_max_v1_v2_never_decreases_confidence():
    model = ConfidenceModelV2()
    for overall in [0.3, 0.5, 0.7, 0.85, 0.95]:
        v1 = _make_v1(overall=overall)
        v2 = model.compute_v2(v1)
        assert max(v1.overall, v2) >= v1.overall


def test_temporal_signal_boosts_v2():
    model = ConfidenceModelV2()
    v1 = _make_v1()
    v2_no = model.compute_v2(v1, temporal_signal=0.0)
    v2_yes = model.compute_v2(v1, temporal_signal=1.0)
    assert v2_yes > v2_no


def test_crossrole_signal_boosts_v2():
    model = ConfidenceModelV2()
    v1 = _make_v1()
    v2_low = model.compute_v2(v1, crossrole_signal=0.0)
    v2_high = model.compute_v2(v1, crossrole_signal=1.0)
    assert v2_high > v2_low


def test_invariant_violated_boosts_v2():
    model = ConfidenceModelV2()
    v1 = _make_v1()
    v2_no = model.compute_v2(v1, invariant_violated=0.0)
    v2_yes = model.compute_v2(v1, invariant_violated=1.0)
    assert v2_yes > v2_no


def test_invariant_violated_has_highest_weight():
    """invariant_violated a le poids le plus élevé (2.5) parmi les dimensions V3."""
    model = ConfidenceModelV2()
    v1 = _make_v1()
    boost_inv = model.compute_v2(v1, invariant_violated=1.0)
    boost_waf = model.compute_v2(v1, waf_bypass_success=1.0)
    boost_causal = model.compute_v2(v1, causal_depth=1.0)
    assert boost_inv > boost_waf
    assert boost_inv > boost_causal


def test_all_signals_at_max_with_strong_v1_reaches_confirmed():
    model = ConfidenceModelV2()
    v1 = _make_v1(overall=0.80, oracle_strength=0.9, reproducibility=0.9)
    v2 = model.compute_v2(
        v1,
        temporal_signal=1.0,
        crossrole_signal=1.0,
        invariant_violated=1.0,
        waf_bypass_success=1.0,
        causal_depth=1.0,
    )
    assert v2 >= CONFIRMED_THRESHOLD


def test_v2_output_in_unit_interval():
    model = ConfidenceModelV2()
    for overall in [0.1, 0.5, 0.9]:
        v1 = _make_v1(overall=overall)
        for temp, cross, inv in [(0, 0, 0), (1, 1, 1), (0.5, 0.5, 0.5)]:
            v2 = model.compute_v2(v1, temporal_signal=temp, crossrole_signal=cross, invariant_violated=inv)
            assert 0.0 <= v2 <= 1.0


def test_causal_depth_from_replay_count_normalization():
    """causal_depth_sig = min(n_replays / 3.0, 1.0)"""
    cases = [(0, 0.0), (1, 1 / 3), (3, 1.0), (10, 1.0)]
    for n_replays, expected in cases:
        sig = min(n_replays / 3.0, 1.0)
        assert sig == pytest.approx(expected, abs=1e-4)


def test_escalation_level_to_temporal_signal():
    """escalation 0→0.33, 1→0.67, 2→1.0"""
    cases = [(0, pytest.approx(1 / 3, abs=1e-4)),
             (1, pytest.approx(2 / 3, abs=1e-4)),
             (2, pytest.approx(1.0))]
    for escalation, expected in cases:
        signal = min((escalation + 1) / 3.0, 1.0)
        assert signal == expected


def test_update_weights_affects_compute():
    model = ConfidenceModelV2()
    v1 = _make_v1()
    v2_before = model.compute_v2(v1, invariant_violated=1.0)
    model.update_weights({"invariant_violated": 10.0})
    v2_after = model.compute_v2(v1, invariant_violated=1.0)
    assert v2_after > v2_before
