# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires — FeedbackLoop (V4 Sprint 8)."""
from __future__ import annotations

import math

import pytest

from hdwp.core.ml.models.feedback_loop import (
    DEFAULT_BIAS,
    DEFAULT_WEIGHTS,
    L2_LAMBDA,
    LEARNING_RATE,
    SESSION_DECAY,
    V2_DIMENSIONS,
    FeedbackLoop,
    _sigmoid,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _all_zero_features() -> dict[str, float]:
    return {dim: 0.0 for dim in V2_DIMENSIONS}


def _all_one_features() -> dict[str, float]:
    return {dim: 1.0 for dim in V2_DIMENSIONS}


def _partial_features(**kwargs: float) -> dict[str, float]:
    f = _all_zero_features()
    f.update(kwargs)
    return f


# ── _sigmoid ─────────────────────────────────────────────────────────────────


def test_sigmoid_zero():
    assert _sigmoid(0.0) == pytest.approx(0.5)


def test_sigmoid_large_positive():
    assert _sigmoid(100.0) == pytest.approx(1.0, abs=1e-6)


def test_sigmoid_large_negative():
    assert _sigmoid(-100.0) == pytest.approx(0.0, abs=1e-6)


def test_sigmoid_symmetry():
    assert _sigmoid(2.0) + _sigmoid(-2.0) == pytest.approx(1.0)


# ── FeedbackLoop — construction ───────────────────────────────────────────────


def test_initial_weights_match_defaults():
    fl = FeedbackLoop()
    for dim in V2_DIMENSIONS:
        assert fl.current_weights()[dim] == pytest.approx(DEFAULT_WEIGHTS[dim])


def test_initial_bias():
    fl = FeedbackLoop()
    assert fl.current_bias() == pytest.approx(DEFAULT_BIAS)


def test_initial_n_updates():
    fl = FeedbackLoop()
    assert fl.n_updates == 0


# ── observe — basic ───────────────────────────────────────────────────────────


def test_observe_confirmed_increments_n_updates():
    fl = FeedbackLoop()
    fl.observe(_all_one_features(), "CONFIRMED")
    assert fl.n_updates == 1


def test_observe_refuted_increments_n_updates():
    fl = FeedbackLoop()
    fl.observe(_all_one_features(), "REFUTED")
    assert fl.n_updates == 1


def test_observe_unknown_verdict_ignored():
    fl = FeedbackLoop()
    fl.observe(_all_one_features(), "AMBIGUOUS")
    assert fl.n_updates == 0


def test_observe_empty_verdict_ignored():
    fl = FeedbackLoop()
    fl.observe(_all_one_features(), "")
    assert fl.n_updates == 0


def test_observe_multiple_updates():
    fl = FeedbackLoop()
    for _ in range(5):
        fl.observe(_all_one_features(), "CONFIRMED")
    assert fl.n_updates == 5


# ── observe — gradient direction ─────────────────────────────────────────────


def test_confirmed_prediction_below_one_increases_active_weights():
    """Quand y=1 et y_hat < 1, err > 0 → -lr*err*x < 0 → poids augmentent."""
    fl = FeedbackLoop()
    features = _partial_features(oracle_strength=1.0, reproducibility=0.0)
    # Forcer y_hat << 1 en réduisant le bias temporairement
    fl._bias = -20.0
    w_before = fl.current_weights()["oracle_strength"]
    fl.observe(features, "CONFIRMED")
    # oracle_strength actif (x=1) → devrait augmenter
    assert fl.current_weights()["oracle_strength"] > w_before


def test_refuted_prediction_above_zero_decreases_active_weights():
    """Quand y=0 et y_hat > 0, err > 0 → -lr*err*x < 0 → poids diminuent."""
    fl = FeedbackLoop()
    features = _partial_features(oracle_strength=1.0, reproducibility=0.0)
    # Forcer y_hat >> 0 via bias élevé
    fl._bias = 20.0
    w_before = fl.current_weights()["oracle_strength"]
    fl.observe(features, "REFUTED")
    assert fl.current_weights()["oracle_strength"] < w_before


def test_zero_feature_dimension_not_changed_significantly():
    """Une dimension à 0 ne doit pas être modifiée par le gradient (sauf L2)."""
    fl = FeedbackLoop()
    features = _partial_features(oracle_strength=0.0)  # oracle_strength inactif
    w_before = fl.current_weights()["oracle_strength"]
    fl.observe(features, "CONFIRMED")
    # Seule la L2 agit : changement très faible
    delta = abs(fl.current_weights()["oracle_strength"] - w_before)
    assert delta < LEARNING_RATE * L2_LAMBDA * abs(w_before) + 1e-6


def test_bias_changes_on_update():
    fl = FeedbackLoop()
    # Forcer un err notable : bias très négatif → y_hat ≈ 0, y=1 → err ≈ -1
    fl._bias = -50.0
    bias_before = fl.current_bias()
    fl.observe(_all_zero_features(), "CONFIRMED")
    assert abs(fl.current_bias() - bias_before) > 1e-4


# ── weight clamping ───────────────────────────────────────────────────────────


def test_weights_clamped_max():
    from hdwp.core.ml.models.feedback_loop import WEIGHT_MAX
    fl = FeedbackLoop()
    # Pousser un poids vers la limite max
    fl._weights["oracle_strength"] = WEIGHT_MAX
    fl._bias = -100.0  # y_hat ≈ 0, y=1, err ≈ -1 → gradient négatif → augmentation
    features = _partial_features(oracle_strength=1.0)
    fl.observe(features, "CONFIRMED")
    assert fl.current_weights()["oracle_strength"] <= WEIGHT_MAX


def test_weights_clamped_min():
    from hdwp.core.ml.models.feedback_loop import WEIGHT_MIN
    fl = FeedbackLoop()
    fl._weights["oracle_strength"] = WEIGHT_MIN
    fl._bias = 100.0  # y_hat ≈ 1, y=0, err ≈ +1 → gradient positif → diminution
    features = _partial_features(oracle_strength=1.0)
    fl.observe(features, "REFUTED")
    assert fl.current_weights()["oracle_strength"] >= WEIGHT_MIN


# ── predict ───────────────────────────────────────────────────────────────────


def test_predict_range():
    fl = FeedbackLoop()
    for _ in range(10):
        import random
        features = {dim: random.random() for dim in V2_DIMENSIONS}
        p = fl.predict(features)
        assert 0.0 <= p <= 1.0


def test_predict_all_zeros_low():
    """Avec toutes features à 0 et bias négatif par défaut, pred doit être < 0.5."""
    fl = FeedbackLoop()
    p = fl.predict(_all_zero_features())
    assert p < 0.5


def test_predict_after_many_confirmed_increases():
    """Après CONFIRMED sur des features actives partant d'un score bas, la prédiction monte."""
    fl = FeedbackLoop()
    # Partir d'un bias très négatif pour que la prédiction de départ soit < 0.5
    fl._bias = -20.0
    features = _all_one_features()
    p_before = fl.predict(features)
    assert p_before < 0.5
    for _ in range(50):
        fl.observe(features, "CONFIRMED")
    p_after = fl.predict(features)
    assert p_after > p_before


def test_predict_after_many_refuted_decreases():
    fl = FeedbackLoop()
    features = _all_one_features()
    p_before = fl.predict(features)
    for _ in range(50):
        fl.observe(features, "REFUTED")
    p_after = fl.predict(features)
    assert p_after < p_before


# ── apply_session_decay ───────────────────────────────────────────────────────


def test_session_decay_no_update_no_op():
    """Sans mises à jour, decay ne fait qu'attirer vers les défauts."""
    fl = FeedbackLoop()
    fl.apply_session_decay()
    assert fl.n_updates == 0
    # Les poids sont déjà aux défauts → restent aux défauts
    for dim in V2_DIMENSIONS:
        expected = DEFAULT_WEIGHTS[dim] * SESSION_DECAY + DEFAULT_WEIGHTS[dim] * (1 - SESSION_DECAY)
        assert fl.current_weights()[dim] == pytest.approx(expected)


def test_session_decay_moves_weights_toward_defaults():
    fl = FeedbackLoop()
    # Pousser un poids loin du défaut
    fl._weights["oracle_strength"] = 5.0
    default = DEFAULT_WEIGHTS["oracle_strength"]
    fl._n_updates = 10  # simuler session précédente
    fl.apply_session_decay()
    new_w = fl.current_weights()["oracle_strength"]
    # Doit se rapprocher du défaut
    assert abs(new_w - default) < abs(5.0 - default)


def test_session_decay_bias_toward_default():
    fl = FeedbackLoop()
    fl._bias = 10.0
    fl._n_updates = 5
    fl.apply_session_decay()
    assert abs(fl.current_bias() - DEFAULT_BIAS) < abs(10.0 - DEFAULT_BIAS)


# ── Persistence ───────────────────────────────────────────────────────────────


def test_to_serializable_structure():
    fl = FeedbackLoop()
    fl.observe(_all_one_features(), "CONFIRMED")
    data = fl.to_serializable()
    assert "weights" in data
    assert "bias" in data
    assert "n_updates" in data
    assert "updated_at" in data
    assert data["n_updates"] == 1
    assert len(data["weights"]) == len(V2_DIMENSIONS)


def test_load_serializable_restores_weights():
    fl1 = FeedbackLoop()
    for _ in range(20):
        fl1.observe(_all_one_features(), "CONFIRMED")
    data = fl1.to_serializable()

    fl2 = FeedbackLoop()
    fl2.load_serializable(data)

    assert fl2.n_updates == 20
    for dim in V2_DIMENSIONS:
        assert fl2.current_weights()[dim] == pytest.approx(fl1.current_weights()[dim], abs=1e-5)
    assert fl2.current_bias() == pytest.approx(fl1.current_bias(), abs=1e-5)


def test_load_serializable_empty_noop():
    fl = FeedbackLoop()
    fl.load_serializable({})
    for dim in V2_DIMENSIONS:
        assert fl.current_weights()[dim] == pytest.approx(DEFAULT_WEIGHTS[dim])


def test_roundtrip_preserves_predictions():
    fl1 = FeedbackLoop()
    for _ in range(10):
        fl1.observe(_partial_features(oracle_strength=0.8, crossrole_signal=0.9), "CONFIRMED")
    data = fl1.to_serializable()

    fl2 = FeedbackLoop()
    fl2.load_serializable(data)

    test_feats = _partial_features(oracle_strength=0.8, crossrole_signal=0.9)
    assert fl1.predict(test_feats) == pytest.approx(fl2.predict(test_feats), abs=1e-5)


# ── drift ────────────────────────────────────────────────────────────────────


def test_drift_zero_initially():
    fl = FeedbackLoop()
    d = fl.drift()
    for dim in V2_DIMENSIONS:
        assert d[dim] == pytest.approx(0.0)


def test_drift_nonzero_after_updates():
    fl = FeedbackLoop()
    for _ in range(20):
        fl.observe(_all_one_features(), "CONFIRMED")
    d = fl.drift()
    # Au moins une dimension doit avoir drifté
    assert any(v > 0.001 for v in d.values())


# ── stats ────────────────────────────────────────────────────────────────────


def test_stats_structure():
    fl = FeedbackLoop()
    s = fl.stats()
    assert "n_updates" in s
    assert "bias" in s
    assert "weights" in s
    assert "drift" in s
    assert len(s["weights"]) == len(V2_DIMENSIONS)


# ── current_weights returns copy ─────────────────────────────────────────────


def test_current_weights_returns_copy():
    fl = FeedbackLoop()
    w = fl.current_weights()
    w["oracle_strength"] = 999.0
    assert fl.current_weights()["oracle_strength"] != 999.0
