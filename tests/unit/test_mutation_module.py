# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
from hdwp.core.experiment.mutation_module import MutationModule, _replace_first_id_in_path
from hdwp.core.experiment.request_selector import ConcreteExperimentPlan
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import ExperimentSpec, NormalizedRequest


def _req(
    url: str = "http://test/api/users/1",
    method: str = "GET",
    headers: dict | None = None,
    body: object = None,
    query_params: dict | None = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        url=url,
        headers=headers or {},
        body=body,
        query_params=query_params or {},
        path_params={},
    )


def _spec(mutation_type: str = "identity_swap") -> ExperimentSpec:
    return ExperimentSpec(
        mutation_type=mutation_type,
        base_request=_req(),
        mutation_params={},
        description="test",
    )


def _plan(
    mutation_type: str = "identity_swap",
    baseline: NormalizedRequest | None = None,
    target_role: str | None = "user_b",
    mutated_value: str | None = None,
    mutated_param_name: str | None = None,
    mutated_param_location: str | None = None,
) -> ConcreteExperimentPlan:
    return ConcreteExperimentPlan(
        hypothesis_id="HYP-test",
        mutation_type=mutation_type,
        baseline_request=baseline or _req(),
        baseline_role="user_a",
        target_role=target_role,
        mutated_value=mutated_value,
        mutated_param_name=mutated_param_name,
        mutated_param_location=mutated_param_location,
        description="test plan",
        experiment_spec=_spec(mutation_type),
    )


def _session_manager(*roles: tuple[str, str]) -> SessionManager:
    """Create a SessionManager with bearer-token roles."""
    role_configs = [
        RoleConfig(name=name, credentials=CredentialConfig(type="bearer", token=token))
        for name, token in roles
    ]
    return SessionManager(role_configs)


module = MutationModule()


# ── identity_swap ─────────────────────────────────────────────────────────

def test_identity_swap_replaces_auth_header() -> None:
    sm = _session_manager(("user_a", "token_a"), ("user_b", "token_b"))
    plan = _plan(mutation_type="identity_swap", target_role="user_b")
    mutated = module.apply(plan, sm)
    assert mutated.headers.get("Authorization") == "Bearer token_b"


def test_identity_swap_does_not_mutate_original() -> None:
    sm = _session_manager(("user_a", "token_a"), ("user_b", "token_b"))
    orig_headers = {"Authorization": "Bearer token_a"}
    baseline = _req(headers=orig_headers)
    plan = _plan(mutation_type="identity_swap", baseline=baseline, target_role="user_b")
    module.apply(plan, sm)
    assert plan.baseline_request.headers.get("Authorization") == "Bearer token_a"


# ── object_ref_change / path ──────────────────────────────────────────────

def test_object_ref_change_path_replaces_numeric_segment() -> None:
    baseline = _req(url="http://test/api/users/42")
    plan = _plan(
        mutation_type="object_ref_change",
        baseline=baseline,
        mutated_value="99",
        mutated_param_name="id",
        mutated_param_location="path",
    )
    mutated = module.apply(plan, _session_manager())
    assert "/api/users/99" in mutated.url


def test_object_ref_change_path_no_numeric_unchanged() -> None:
    baseline = _req(url="http://test/api/items")
    plan = _plan(
        mutation_type="object_ref_change",
        baseline=baseline,
        mutated_value="99",
        mutated_param_name="id",
        mutated_param_location="path",
    )
    mutated = module.apply(plan, _session_manager())
    assert mutated.url == "http://test/api/items"


# ── object_ref_change / query ─────────────────────────────────────────────

def test_object_ref_change_query_updates_param() -> None:
    baseline = _req(url="http://test/api/items?user_id=1", query_params={"user_id": "1"})
    plan = _plan(
        mutation_type="object_ref_change",
        baseline=baseline,
        mutated_value="2",
        mutated_param_name="user_id",
        mutated_param_location="query",
    )
    mutated = module.apply(plan, _session_manager())
    assert mutated.query_params["user_id"] == "2"
    assert "user_id=2" in mutated.url


# ── object_ref_change / body ──────────────────────────────────────────────

def test_object_ref_change_body_updates_field() -> None:
    baseline = _req(body={"item_id": 5, "name": "foo"})
    plan = _plan(
        mutation_type="object_ref_change",
        baseline=baseline,
        mutated_value="9",
        mutated_param_name="item_id",
        mutated_param_location="body",
    )
    mutated = module.apply(plan, _session_manager())
    assert mutated.body == {"item_id": "9", "name": "foo"}  # type: ignore[index]


# ── privilege_escalation ──────────────────────────────────────────────────

def test_privilege_escalation_replaces_auth_header() -> None:
    sm = _session_manager(("admin", "token_admin"), ("user_a", "token_a"))
    baseline = _req(headers={"Authorization": "Bearer token_admin"})
    plan = _plan(
        mutation_type="privilege_escalation",
        baseline=baseline,
        target_role="user_a",
    )
    mutated = module.apply(plan, sm)
    assert mutated.headers.get("Authorization") == "Bearer token_a"


# ── unknown mutation type ─────────────────────────────────────────────────

def test_unknown_mutation_type_returns_baseline() -> None:
    baseline = _req(url="http://test/api/items/7")
    plan = _plan(mutation_type="unknown_type", baseline=baseline)
    mutated = module.apply(plan, _session_manager())
    assert mutated.url == baseline.url


# ── _replace_first_id_in_path helper ─────────────────────────────────────

def test_replace_path_leaves_non_numeric_unchanged() -> None:
    result = _replace_first_id_in_path("http://test/api/profile", "99")
    assert result == "http://test/api/profile"


def test_replace_path_uuid() -> None:
    url = "http://test/api/objects/550e8400-e29b-41d4-a716-446655440000"
    result = _replace_first_id_in_path(url, "new-uuid")
    assert "new-uuid" in result
