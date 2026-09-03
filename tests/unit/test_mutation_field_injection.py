# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.experiment.mutation_module import MutationModule
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import ConcreteExperimentPlan, ExperimentSpec, NormalizedRequest
from hdwp.core.context.config_schema import RoleConfig


def _make_plan(
    location: str,
    payload: str,
    param: str = "q",
    body: object = None,
    url: str = "http://test/api/search?q=hello",
) -> ConcreteExperimentPlan:
    spec = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url=url),
        mutation_params={"payload_type": "sqli", "payload": payload},
    )
    req = NormalizedRequest(
        method="GET",
        url=url,
        query_params={"q": "hello"} if location == "query" else {},
        body=body,
    )
    return ConcreteExperimentPlan(
        hypothesis_id="HYP-test",
        mutation_type="field_injection",
        baseline_request=req,
        baseline_role="anonymous",
        target_role=None,
        mutated_value=payload,
        mutated_param_name=param,
        mutated_param_location=location,
        description="test",
        experiment_spec=spec,
    )


def test_field_injection_query() -> None:
    plan = _make_plan("query", "' OR '1'='1")
    sm = SessionManager([RoleConfig(name="anonymous")])
    mutated = MutationModule().apply(plan, sm)
    # URL is percent-encoded, but query_params holds the raw value
    assert mutated.query_params.get("q") == "' OR '1'='1"
    # URL changed from original
    assert mutated.url != plan.baseline_request.url


def test_field_injection_body() -> None:
    plan = _make_plan(
        "body", "<script>alert(1)</script>",
        param="name",
        body={"name": "Alice", "email": "alice@example.com"},
        url="http://test/api/update",
    )
    sm = SessionManager([RoleConfig(name="anonymous")])
    mutated = MutationModule().apply(plan, sm)
    assert isinstance(mutated.body, dict)
    assert mutated.body["name"] == "<script>alert(1)</script>"
    # Other fields preserved
    assert mutated.body["email"] == "alice@example.com"


def test_field_injection_path() -> None:
    plan = _make_plan(
        "path", "{{7*7}}",
        param="id",
        url="http://test/api/users/42",
    )
    sm = SessionManager([RoleConfig(name="anonymous")])
    mutated = MutationModule().apply(plan, sm)
    assert "{{7*7}}" in mutated.url
    assert "42" not in mutated.url


def test_field_injection_does_not_mutate_original() -> None:
    plan = _make_plan("query", "' OR '1'='1")
    original_url = plan.baseline_request.url
    sm = SessionManager([RoleConfig(name="anonymous")])
    MutationModule().apply(plan, sm)
    assert plan.baseline_request.url == original_url


def test_field_injection_unknown_location_returns_unchanged() -> None:
    plan = _make_plan("header", "payload")
    sm = SessionManager([RoleConfig(name="anonymous")])
    mutated = MutationModule().apply(plan, sm)
    assert mutated == plan.baseline_request
