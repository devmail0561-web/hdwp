# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re

import pytest

from hdwp.core.experiment.request_selector import RequestSelector, fallback_probe_values
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    ParameterNode,
    RoleNode,
)


def _make_hyp(param_name: str = "path_0", location: str = "path") -> Hypothesis:
    return Hypothesis(
        source_plugin="test",
        property_id="PROP-test",
        statement="test",
        required_experiments=[
            ExperimentSpec(
                mutation_type="object_ref_change",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={"parameter_name": param_name, "parameter_location": location},
                description="test",
            )
        ],
    )


def _make_model() -> ApplicationModelData:
    return ApplicationModelData(
        roles=[RoleNode(id="R1", name="user_a")],
        parameters=[ParameterNode(id="P1", name="path_0", location="path", type_inferred="integer", affects_object="OBJ-1")],
    )


def _make_corpus(role: str, url: str) -> dict:
    req = NormalizedRequest(method="GET", url=url)
    path = "/" + "/".join(url.split("/")[3:])  # rough path extraction
    return {path: [(role, req)]}


@pytest.mark.asyncio
async def test_single_role_integer_generates_multiple_probes() -> None:
    selector = RequestSelector()
    hyp = _make_hyp()
    model = _make_model()
    corpus = {"/api/users/{id_0}": [("user_a", NormalizedRequest(method="GET", url="http://t/api/users/5"))]}

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    assert len(plans) >= 2, f"Expected ≥2 plans, got {len(plans)}"
    values = [p.mutated_value for p in plans]
    # Should not include the original value
    assert "5" not in values
    # Should include small integers
    assert any(v in ("1", "2", "3", "4", "6") for v in values)


@pytest.mark.asyncio
async def test_single_role_uuid_generates_uuid_probes() -> None:
    selector = RequestSelector()
    hyp = _make_hyp()
    model = ApplicationModelData(
        roles=[RoleNode(id="R1", name="user_a")],
        parameters=[ParameterNode(id="P1", name="path_0", location="path", type_inferred="uuid", affects_object="OBJ-1")],
    )
    test_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    corpus = {"/api/items/{uuid_0}": [("user_a", NormalizedRequest(method="GET", url=f"http://t/api/items/{test_uuid}"))]}

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    assert len(plans) >= 1
    for p in plans:
        assert p.mutated_value != test_uuid
        assert uuid_re.match(p.mutated_value or ""), f"Expected UUID, got {p.mutated_value}"


@pytest.mark.asyncio
async def test_cross_role_prioritised_over_fallback() -> None:
    selector = RequestSelector()
    hyp = _make_hyp()
    model = ApplicationModelData(
        roles=[RoleNode(id="R1", name="user_a"), RoleNode(id="R2", name="user_b")],
        parameters=[ParameterNode(id="P1", name="path_0", location="path", type_inferred="integer", affects_object="OBJ-1")],
    )
    corpus = {
        "/api/users/{id_0}": [
            ("user_a", NormalizedRequest(method="GET", url="http://t/api/users/1")),
            ("user_b", NormalizedRequest(method="GET", url="http://t/api/users/2")),
        ]
    }

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    assert len(plans) >= 1
    # Cross-role plan should use actual observed value from the other role
    plan = plans[0]
    assert plan.mutated_value == "2"
    assert plan.baseline_role == "user_a"


@pytest.mark.asyncio
async def test_probe_values_do_not_include_current_value() -> None:
    probes = fallback_probe_values("42")
    assert "42" not in probes


@pytest.mark.asyncio
async def test_probe_values_max_three() -> None:
    probes = fallback_probe_values("100")
    assert len(probes) <= 3


@pytest.mark.asyncio
async def test_probe_values_for_id_1_excludes_zero_and_negatives() -> None:
    probes = fallback_probe_values("1")
    for v in probes:
        assert int(v) > 0
