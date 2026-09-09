# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for MutationModule.apply() — transport bypass integration (Phase 2)."""

from __future__ import annotations

import pytest

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
from hdwp.core.experiment.mutation_module import MutationModule
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import ConcreteExperimentPlan, ExperimentSpec, NormalizedRequest
from hdwp.core.payloads.waf_bypass.bypass_registry import BypassRegistry


@pytest.fixture(autouse=True)
def reset_bypass_registry():
    BypassRegistry.reset_for_testing()
    yield
    BypassRegistry.reset_for_testing()


def _req(
    url: str = "http://target/api/resource",
    method: str = "GET",
    headers: dict | None = None,
    body: object = None,
    query_params: dict | None = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        url=url,
        headers=headers or {"Content-Type": "application/json"},
        body=body,
        query_params=query_params or {},
        path_params={},
    )


def _plan(
    mutation_type: str = "identity_swap",
    mutation_params: dict | None = None,
    baseline: NormalizedRequest | None = None,
) -> ConcreteExperimentPlan:
    spec = ExperimentSpec(
        mutation_type=mutation_type,
        base_request=baseline or _req(),
        mutation_params=mutation_params or {},
        description="test",
    )
    return ConcreteExperimentPlan(
        hypothesis_id="HYP-test",
        mutation_type=mutation_type,
        baseline_request=baseline or _req(),
        baseline_role="user_a",
        target_role="user_b",
        mutated_value=None,
        mutated_param_name=None,
        mutated_param_location=None,
        description="test plan",
        experiment_spec=spec,
    )


def _sm() -> SessionManager:
    return SessionManager([
        RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="tok_a")),
        RoleConfig(name="user_b", credentials=CredentialConfig(type="bearer", token="tok_b")),
    ])


module = MutationModule()


# ── No bypass (zero regression) ───────────────────────────────────────────

class TestNoBypass:
    def test_without_transport_bypass_behaves_as_before(self):
        plan = _plan(mutation_params={})
        result = module.apply(plan, _sm())
        assert result is not None
        assert result.raw_body_override is None

    def test_result_is_normalized_request(self):
        plan = _plan()
        result = module.apply(plan, _sm())
        assert isinstance(result, NormalizedRequest)


# ── With transport bypass ─────────────────────────────────────────────────

class TestWithTransportBypass:
    def test_whitespace_variation_modifies_xff_header(self):
        plan = _plan(mutation_params={"_transport_bypass": "whitespace_variation"})
        result = module.apply(plan, _sm())
        assert "X-Forwarded-For" in result.headers
        assert result.headers["X-Forwarded-For"].endswith("\t")

    def test_rate_limit_evasion_adds_ip_headers(self):
        plan = _plan(mutation_params={"_transport_bypass": "rate_limit_evasion"})
        result = module.apply(plan, _sm())
        assert "X-Real-IP" in result.headers

    def test_tls_fingerprint_sets_user_agent(self):
        plan = _plan(mutation_params={"_transport_bypass": "tls_fingerprint"})
        result = module.apply(plan, _sm())
        assert "Chrome" in result.headers.get("User-Agent", "")

    def test_chunked_abuse_sets_raw_body_override(self):
        req = _req(body="injection_payload")
        plan = _plan(
            mutation_params={"_transport_bypass": "chunked_abuse"},
            baseline=req,
        )
        result = module.apply(plan, _sm())
        assert result.raw_body_override is not None
        assert b";waf=bypass" in result.raw_body_override

    def test_cl_te_smuggling_sets_raw_body_override(self):
        req = _req(body="payload_data")
        plan = _plan(
            mutation_params={"_transport_bypass": "cl_te_smuggling"},
            baseline=req,
        )
        result = module.apply(plan, _sm())
        assert result.raw_body_override is not None

    def test_hpp_modifies_url(self):
        req = _req(url="http://target/api?id=1", query_params={"id": "1"})
        plan = _plan(
            mutation_params={"_transport_bypass": "hpp", "target_param": "id"},
            baseline=req,
        )
        result = module.apply(plan, _sm())
        assert result.url.count("id=") == 2


# ── Unknown bypass (graceful degradation) ────────────────────────────────

class TestUnknownBypass:
    def test_unknown_bypass_returns_valid_request(self):
        plan = _plan(mutation_params={"_transport_bypass": "nonexistent_strategy_xyz"})
        result = module.apply(plan, _sm())
        assert isinstance(result, NormalizedRequest)

    def test_unknown_bypass_raw_override_is_none(self):
        plan = _plan(mutation_params={"_transport_bypass": "nonexistent_strategy_xyz"})
        result = module.apply(plan, _sm())
        assert result.raw_body_override is None

    def test_exception_in_strategy_returns_valid_request(self):
        from hdwp.core.payloads.waf_bypass.bypass_registry import BypassStrategy

        def bad_apply(req, params):
            raise RuntimeError("strategy exploded")

        registry = BypassRegistry()
        registry.register(BypassStrategy(
            name="exploding_strategy",
            category="evasion",
            apply=bad_apply,
            description="always raises",
        ))

        plan = _plan(mutation_params={"_transport_bypass": "exploding_strategy"})
        result = module.apply(plan, _sm())
        assert isinstance(result, NormalizedRequest)


# ── NormalizedRequest.raw_body_override schema ────────────────────────────

class TestRawBodyOverrideField:
    def test_default_is_none(self):
        req = _req()
        assert req.raw_body_override is None

    def test_can_be_set_to_bytes(self):
        req = _req()
        req2 = req.model_copy(update={"raw_body_override": b"raw bytes"})
        assert req2.raw_body_override == b"raw bytes"

    def test_original_unchanged(self):
        req = _req()
        req.model_copy(update={"raw_body_override": b"x"})
        assert req.raw_body_override is None
