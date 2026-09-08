# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires pour ActiveLearner — V4 Sprint 5."""
from __future__ import annotations

import math
import pytest

from hdwp.core.ml.models.active_learner import (
    ActiveLearner,
    _PRIOR_ENTROPY,
    _MIN_EXPLORATION_WEIGHT,
)


# ── compute_entropy ───────────────────────────────────────────────────────────


class TestComputeEntropy:
    def test_max_entropy_all_half(self):
        probs = {t: 0.5 for t in ["bola", "sqli", "xss"]}
        h = ActiveLearner.compute_entropy(probs)
        assert h == pytest.approx(1.0, abs=1e-6)

    def test_min_entropy_all_zero(self):
        probs = {t: 0.0 for t in ["bola", "sqli", "xss"]}
        h = ActiveLearner.compute_entropy(probs)
        assert h == pytest.approx(0.0, abs=1e-3)

    def test_min_entropy_all_one(self):
        probs = {t: 1.0 for t in ["bola", "sqli"]}
        h = ActiveLearner.compute_entropy(probs)
        assert h == pytest.approx(0.0, abs=1e-3)

    def test_entropy_normalized_to_one(self):
        probs = {t: 0.5 for t in range(9)}
        h = ActiveLearner.compute_entropy(probs)
        assert 0.0 <= h <= 1.0

    def test_empty_returns_prior(self):
        h = ActiveLearner.compute_entropy({})
        assert h == _PRIOR_ENTROPY

    def test_single_certain(self):
        h = ActiveLearner.compute_entropy({"bola": 0.98})
        assert h < 0.2  # H(0.98) ≈ 0.141

    def test_single_uncertain(self):
        h = ActiveLearner.compute_entropy({"bola": 0.5})
        assert h == pytest.approx(1.0, abs=1e-6)

    def test_mixed_probs(self):
        probs = {"bola": 0.9, "sqli": 0.5, "xss": 0.1}
        h = ActiveLearner.compute_entropy(probs)
        assert 0.0 < h < 1.0

    def test_entropy_monotone_near_half(self):
        h1 = ActiveLearner.compute_entropy({"x": 0.4})
        h2 = ActiveLearner.compute_entropy({"x": 0.5})
        h3 = ActiveLearner.compute_entropy({"x": 0.6})
        assert h1 < h2
        assert h3 < h2


# ── exploration_weight ────────────────────────────────────────────────────────


class TestExplorationWeight:
    def test_zero_pulls_weight_one(self):
        w = ActiveLearner.exploration_weight(0)
        assert w == pytest.approx(1.0)

    def test_weight_decreases_with_pulls(self):
        w0 = ActiveLearner.exploration_weight(0)
        w10 = ActiveLearner.exploration_weight(10)
        w100 = ActiveLearner.exploration_weight(100)
        assert w0 > w10 > w100

    def test_weight_bounded_below(self):
        w = ActiveLearner.exploration_weight(10_000)
        assert w >= _MIN_EXPLORATION_WEIGHT

    def test_weight_at_100_pulls(self):
        w = ActiveLearner.exploration_weight(100)
        assert w == pytest.approx(1.0 / 11.0, abs=1e-6)

    def test_weight_never_exceeds_one(self):
        for n in [0, 1, 5, 50, 500]:
            assert ActiveLearner.exploration_weight(n) <= 1.0


# ── update_endpoint_entropy ───────────────────────────────────────────────────


class TestUpdateEndpointEntropy:
    def test_stores_entropy(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/users", {"bola": 0.5, "sqli": 0.5})
        assert al.endpoint_entropy("/api/users") == pytest.approx(1.0, abs=1e-6)

    def test_overwrites_previous(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/users", {"bola": 0.5})
        al.update_endpoint_entropy("/api/users", {"bola": 0.0})
        assert al.endpoint_entropy("/api/users") == pytest.approx(0.0, abs=1e-3)

    def test_unknown_endpoint_returns_prior(self):
        al = ActiveLearner()
        assert al.endpoint_entropy("/api/unknown") == _PRIOR_ENTROPY

    def test_multiple_endpoints_independent(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/a", {"x": 0.5})
        al.update_endpoint_entropy("/api/b", {"x": 0.0})
        assert al.endpoint_entropy("/api/a") > al.endpoint_entropy("/api/b")


# ── combined_score ────────────────────────────────────────────────────────────


class TestCombinedScore:
    def test_zero_pulls_pure_entropy(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/x", {"a": 0.5})  # entropy=1.0
        score = al.combined_score(thompson_score=0.0, endpoint_path="/api/x", total_pulls=0)
        # w=1.0 → score = entropy = 1.0
        assert score == pytest.approx(1.0, abs=1e-6)

    def test_many_pulls_weights_thompson(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/x", {"a": 0.0})  # entropy=0.0
        # total_pulls large → w small → score ≈ thompson_score
        score = al.combined_score(thompson_score=0.8, endpoint_path="/api/x", total_pulls=1000)
        assert score > 0.7  # mostly thompson (0.8)

    def test_no_entropy_data_uses_prior(self):
        al = ActiveLearner()
        score = al.combined_score(0.6, "/unknown", 0)
        # w=1.0, entropy=prior=0.5 → score=0.5
        assert score == pytest.approx(0.5, abs=1e-6)

    def test_score_in_range(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/x", {"a": 0.3, "b": 0.7})
        score = al.combined_score(0.8, "/api/x", 50)
        assert 0.0 <= score <= 1.0


# ── sort_hypotheses ───────────────────────────────────────────────────────────


class TestSortHypotheses:
    def _make_hyp(self, ep_path: str, mutation: str):
        class Spec:
            mutation_type = mutation
            mutation_params = {"endpoint_path": ep_path}

        class Hyp:
            required_experiments = [Spec()]

        return Hyp()

    def test_empty_returns_empty(self):
        al = ActiveLearner()
        assert al.sort_hypotheses([], None) == []

    def test_preserves_count(self):
        al = ActiveLearner()

        class Model:
            endpoints = []

        hyps = [self._make_hyp("/api/x", "sqli") for _ in range(5)]
        assert len(al.sort_hypotheses(hyps, Model())) == 5

    def test_no_entropy_no_optimizer_returns_unchanged(self):
        al = ActiveLearner()
        hyps = [self._make_hyp("/api/x", "sqli")]
        result = al.sort_hypotheses(hyps, None)
        assert result == hyps

    def test_high_entropy_endpoint_ranked_first(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/uncertain", {"a": 0.5, "b": 0.5})
        al.update_endpoint_entropy("/api/certain", {"a": 0.0, "b": 0.0})

        class Model:
            endpoints = []

        hyp_uncertain = self._make_hyp("/api/uncertain", "sqli")
        hyp_certain = self._make_hyp("/api/certain", "sqli")

        wins = 0
        for _ in range(30):
            result = al.sort_hypotheses([hyp_uncertain, hyp_certain], Model())
            if result[0] is hyp_uncertain:
                wins += 1
        assert wins >= 25  # uncertain endpoint doit dominer

    def test_sort_with_optimizer(self):
        """Avec optimizer entraîné, l'exploitation prend le dessus sur de nombreux pulls."""
        from hdwp.core.ml.models.payload_optimizer import ArmState, PayloadOptimizer

        al = ActiveLearner()
        al.update_endpoint_entropy("/api/ep", {"a": 0.0})  # entropy basse

        class EP:
            methods = ["GET"]
            auth_required = False
            path = "/api/ep"
            response_content_type = None

        class Model:
            endpoints = [EP()]

        opt = PayloadOptimizer()
        fp = opt.fingerprint_from_endpoint(EP())
        # Entraîner field_injection comme bon, sqli comme mauvais
        for _ in range(50):
            opt.update(fp, "field_injection", "CONFIRMED")
        for _ in range(50):
            opt.update(fp, "sqli", "REFUTED")

        hyp_fi = self._make_hyp("/api/ep", "field_injection")
        hyp_sq = self._make_hyp("/api/ep", "sqli")

        wins = 0
        for _ in range(50):
            result = al.sort_hypotheses([hyp_fi, hyp_sq], Model(), optimizer=opt)
            if result[0] is hyp_fi:
                wins += 1
        # Avec 100 pulls totaux, w ≈ 0.09 → Thompson domine → field_injection premier
        assert wins >= 30


# ── stats ─────────────────────────────────────────────────────────────────────


class TestStats:
    def test_empty_stats(self):
        al = ActiveLearner()
        s = al.stats()
        assert s["n_endpoints_with_entropy"] == 0
        assert s["mean_entropy"] == 0.0

    def test_stats_populated(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/a", {"x": 0.5})
        al.update_endpoint_entropy("/api/b", {"x": 0.1})
        s = al.stats()
        assert s["n_endpoints_with_entropy"] == 2
        assert 0.0 < s["mean_entropy"] <= 1.0

    def test_high_uncertainty_endpoints_listed(self):
        al = ActiveLearner()
        al.update_endpoint_entropy("/api/uncertain", {"a": 0.5})  # H=1.0 > 0.7
        al.update_endpoint_entropy("/api/certain", {"a": 0.01})   # H très bas
        s = al.stats()
        assert "/api/uncertain" in s["high_uncertainty_endpoints"]
        assert "/api/certain" not in s["high_uncertainty_endpoints"]
