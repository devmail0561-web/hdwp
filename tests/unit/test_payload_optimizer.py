# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires pour PayloadOptimizer — V4 Sprint 4."""
from __future__ import annotations

import pytest

from hdwp.core.ml.models.payload_optimizer import (
    ArmState,
    PayloadOptimizer,
    _extract_hyp_endpoint,
    _hyp_mutation,
)


# ── ArmState ──────────────────────────────────────────────────────────────────


class TestArmState:
    def test_initial_prior_uniform(self):
        arm = ArmState()
        assert arm.alpha == 1.0
        assert arm.beta == 1.0
        assert arm.pulls == 0

    def test_estimated_rate_initial(self):
        arm = ArmState()
        assert arm.estimated_rate == pytest.approx(0.5)

    def test_update_confirmed(self):
        arm = ArmState()
        arm.update(1.0)
        assert arm.alpha == pytest.approx(2.0)
        assert arm.beta == pytest.approx(1.0)
        assert arm.pulls == 1

    def test_update_refuted(self):
        arm = ArmState()
        arm.update(0.0)
        assert arm.alpha == pytest.approx(1.0)
        assert arm.beta == pytest.approx(2.0)
        assert arm.pulls == 1

    def test_update_ambiguous(self):
        arm = ArmState()
        arm.update(0.3)
        assert arm.alpha == pytest.approx(1.3)
        assert arm.beta == pytest.approx(1.7)
        assert arm.pulls == 1

    def test_sample_returns_float_in_range(self):
        arm = ArmState(alpha=3.0, beta=1.0)
        for _ in range(20):
            s = arm.sample()
            assert 0.0 <= s <= 1.0

    def test_high_alpha_biases_sample(self):
        arm_good = ArmState(alpha=100.0, beta=1.0)
        arm_bad = ArmState(alpha=1.0, beta=100.0)
        # Over many samples, good arm should average higher
        avg_good = sum(arm_good.sample() for _ in range(200)) / 200
        avg_bad = sum(arm_bad.sample() for _ in range(200)) / 200
        assert avg_good > avg_bad


# ── Fingerprinting ────────────────────────────────────────────────────────────


class TestFingerprint:
    def test_fingerprint_from_request_get_no_auth(self):
        class Req:
            method = "GET"
            headers = {}
            url = "/api/products"
        fp = PayloadOptimizer.fingerprint_from_request(Req())
        assert fp == "GET:0:0:none"

    def test_fingerprint_from_request_post_auth_json(self):
        class Req:
            method = "POST"
            headers = {"Authorization": "Bearer xyz", "Content-Type": "application/json"}
            url = "/api/users/42/orders"
        fp = PayloadOptimizer.fingerprint_from_request(Req())
        assert fp == "POST:1:1:json"

    def test_fingerprint_from_request_delete_uuid(self):
        class Req:
            method = "DELETE"
            headers = {}
            url = "/api/items/550e8400-e29b-41d4-a716-446655440000"
        fp = PayloadOptimizer.fingerprint_from_request(Req())
        assert fp == "DELETE:0:1:none"

    def test_fingerprint_from_request_form(self):
        class Req:
            method = "POST"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            url = "/login"
        fp = PayloadOptimizer.fingerprint_from_request(Req())
        assert fp == "POST:0:0:form"

    def test_fingerprint_from_request_unknown_method(self):
        class Req:
            method = "PROPFIND"
            headers = {}
            url = "/api"
        fp = PayloadOptimizer.fingerprint_from_request(Req())
        assert fp.startswith("OTHER:")

    def test_fingerprint_from_endpoint_basic(self):
        class EP:
            methods = ["GET"]
            auth_required = False
            path = "/api/public"
            response_content_type = None
        fp = PayloadOptimizer.fingerprint_from_endpoint(EP())
        assert fp == "GET:0:0:none"

    def test_fingerprint_from_endpoint_auth_path_params(self):
        class EP:
            methods = ["PUT"]
            auth_required = True
            path = "/api/users/{user_id}/profile"
            response_content_type = "application/json"
        fp = PayloadOptimizer.fingerprint_from_endpoint(EP())
        assert fp == "PUT:1:1:json"

    def test_fingerprint_from_url(self):
        fp = PayloadOptimizer.fingerprint_from_url("/api/orders/42", auth_required=True)
        assert fp == "GET:1:1:none"

    def test_fingerprint_stable_on_repeated_calls(self):
        class Req:
            method = "GET"
            headers = {"Cookie": "session=abc"}
            url = "/api/v2/data"
        opt = PayloadOptimizer()
        fp1 = opt.fingerprint_from_request(Req())
        fp2 = opt.fingerprint_from_request(Req())
        assert fp1 == fp2


# ── Bandit logic ──────────────────────────────────────────────────────────────


class TestPayloadOptimizerBandit:
    def test_update_confirmed_increments_alpha(self):
        opt = PayloadOptimizer()
        opt.update("POST:1:0:json", "field_injection", "CONFIRMED")
        arm = opt._arm("POST:1:0:json", "field_injection")
        assert arm.alpha == pytest.approx(2.0)
        assert arm.beta == pytest.approx(1.0)
        assert arm.pulls == 1

    def test_update_refuted_increments_beta(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:1:none", "identity_swap", "REFUTED")
        arm = opt._arm("GET:0:1:none", "identity_swap")
        assert arm.alpha == pytest.approx(1.0)
        assert arm.beta == pytest.approx(2.0)

    def test_update_ambiguous_partial_reward(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:0:none", "jwt_manipulation", "INSUFFICIENT_DATA")
        arm = opt._arm("GET:0:0:none", "jwt_manipulation")
        assert arm.alpha == pytest.approx(1.3)

    def test_total_pulls_counts_all_updates(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:0:none", "field_injection", "CONFIRMED")
        opt.update("POST:1:0:json", "identity_swap", "REFUTED")
        opt.update("GET:0:0:none", "field_injection", "REFUTED")
        assert opt.total_pulls == 3

    def test_suggest_order_returns_same_set(self):
        opt = PayloadOptimizer()
        mutations = ["field_injection", "identity_swap", "jwt_manipulation"]
        ordered = opt.suggest_order("POST:1:0:json", mutations)
        assert set(ordered) == set(mutations)
        assert len(ordered) == 3

    def test_suggest_order_biased_after_training(self):
        opt = PayloadOptimizer()
        fp = "POST:1:0:json"
        for _ in range(20):
            opt.update(fp, "field_injection", "CONFIRMED")
        for _ in range(20):
            opt.update(fp, "identity_swap", "REFUTED")

        wins = 0
        for _ in range(50):
            ordered = opt.suggest_order(fp, ["field_injection", "identity_swap"])
            if ordered[0] == "field_injection":
                wins += 1
        # field_injection devrait être premier dans la grande majorité des tirages
        assert wins >= 35

    def test_n_arms_grows_lazily(self):
        opt = PayloadOptimizer()
        assert opt.n_arms == 0
        opt.update("GET:0:0:none", "sqli", "CONFIRMED")
        assert opt.n_arms == 1
        opt.update("GET:0:0:none", "xss", "REFUTED")
        assert opt.n_arms == 2


# ── sort_hypotheses ───────────────────────────────────────────────────────────


class TestSortHypotheses:
    def _make_hyp(self, ep_path: str, mutation: str):
        class Spec:
            mutation_type = mutation
            mutation_params = {"endpoint_path": ep_path}

        class Hyp:
            required_experiments = [Spec()]

        return Hyp()

    def test_empty_list(self):
        opt = PayloadOptimizer()
        assert opt.sort_hypotheses([], None) == []

    def test_returns_same_count(self):
        opt = PayloadOptimizer()

        class Model:
            endpoints = []

        hyps = [self._make_hyp("/api/users", "sqli") for _ in range(5)]
        result = opt.sort_hypotheses(hyps, Model())
        assert len(result) == 5

    def test_ordering_respects_trained_arms(self):
        opt = PayloadOptimizer()

        class EP:
            methods = ["POST"]
            auth_required = True
            path = "/api/users/{id}"
            response_content_type = "application/json"

        class Model:
            endpoints = [EP()]

        fp = opt.fingerprint_from_endpoint(EP())
        # Entraîner field_injection comme très bon, sqli comme mauvais
        for _ in range(30):
            opt.update(fp, "field_injection", "CONFIRMED")
        for _ in range(30):
            opt.update(fp, "sqli", "REFUTED")

        hyps = [
            self._make_hyp("/api/users/{id}", "sqli"),
            self._make_hyp("/api/users/{id}", "field_injection"),
        ]
        wins = 0
        for _ in range(30):
            result = opt.sort_hypotheses(hyps, Model())
            if _hyp_mutation(result[0]) == "field_injection":
                wins += 1
        assert wins >= 20


# ── Persistence ───────────────────────────────────────────────────────────────


class TestPersistence:
    def test_to_serializable_structure(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:0:none", "sqli", "CONFIRMED")
        stats = opt.to_serializable()
        assert len(stats) == 1
        s = stats[0]
        assert s["fingerprint"] == "GET:0:0:none"
        assert s["mutation_type"] == "sqli"
        assert s["alpha"] == pytest.approx(2.0)
        assert s["beta"] == pytest.approx(1.0)
        assert s["pulls"] == 1

    def test_load_serializable_restores_arms(self):
        opt = PayloadOptimizer()
        data = [
            {"fingerprint": "POST:1:0:json", "mutation_type": "field_injection",
             "alpha": 10.0, "beta": 2.0, "pulls": 11},
        ]
        opt.load_serializable(data)
        arm = opt._arm("POST:1:0:json", "field_injection")
        assert arm.alpha == pytest.approx(10.0)
        assert arm.beta == pytest.approx(2.0)
        assert arm.pulls == 11

    def test_roundtrip_serialization(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:1:none", "identity_swap", "CONFIRMED")
        opt.update("GET:0:1:none", "identity_swap", "CONFIRMED")
        opt.update("POST:1:0:json", "sqli", "REFUTED")

        serialized = opt.to_serializable()
        opt2 = PayloadOptimizer()
        opt2.load_serializable(serialized)

        arm1 = opt2._arm("GET:0:1:none", "identity_swap")
        assert arm1.alpha == pytest.approx(3.0)
        assert arm1.beta == pytest.approx(1.0)
        assert arm1.pulls == 2

    def test_load_serializable_skips_empty_keys(self):
        opt = PayloadOptimizer()
        data = [
            {"fingerprint": "", "mutation_type": "sqli", "alpha": 5.0, "beta": 1.0, "pulls": 5},
            {"fingerprint": "GET:0:0:none", "mutation_type": "", "alpha": 5.0, "beta": 1.0, "pulls": 5},
        ]
        opt.load_serializable(data)
        assert opt.n_arms == 0

    def test_stats_sorted_by_estimated_rate(self):
        opt = PayloadOptimizer()
        opt.update("GET:0:0:none", "sqli", "CONFIRMED")
        opt.update("GET:0:0:none", "sqli", "CONFIRMED")
        opt.update("GET:0:0:none", "xss", "REFUTED")
        stats = opt.stats()
        assert stats[0]["mutation_type"] == "sqli"
        assert stats[0]["estimated_rate"] > stats[1]["estimated_rate"]


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_extract_hyp_endpoint_from_params(self):
        class Spec:
            mutation_params = {"endpoint_path": "/api/users/42"}
            mutation_type = "sqli"

        class Hyp:
            required_experiments = [Spec()]

        assert _extract_hyp_endpoint(Hyp()) == "/api/users/42"

    def test_extract_hyp_endpoint_target_endpoint(self):
        class Spec:
            mutation_params = {"target_endpoint": "/api/admin"}
            mutation_type = "identity_swap"

        class Hyp:
            required_experiments = [Spec()]

        assert _extract_hyp_endpoint(Hyp()) == "/api/admin"

    def test_extract_hyp_endpoint_empty(self):
        class Hyp:
            required_experiments = []

        assert _extract_hyp_endpoint(Hyp()) == ""

    def test_hyp_mutation_type(self):
        class Spec:
            mutation_type = "jwt_manipulation"
            mutation_params = {}

        class Hyp:
            required_experiments = [Spec()]

        assert _hyp_mutation(Hyp()) == "jwt_manipulation"

    def test_hyp_mutation_type_no_exps(self):
        class Hyp:
            required_experiments = []

        assert _hyp_mutation(Hyp()) == "unknown"
