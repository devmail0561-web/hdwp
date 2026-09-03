# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.experiment.request_selector import RequestSelector
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConcreteExperimentPlan,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    NormalizedResponse,
    ObservationType,
    RawObservation,
    RoleNode,
)


# ── helpers ───────────────────────────────────────────────────────────────────


def _req(url: str, method: str = "GET", role: str | None = None) -> NormalizedRequest:
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    qp = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    return NormalizedRequest(method=method, url=url, query_params=qp)


def _corpus(
    path: str,
    entries: list[tuple[str, str]],  # (role_name, url)
) -> dict[str, list[tuple[str, NormalizedRequest]]]:
    return {path: [(role, _req(url)) for role, url in entries]}


def _hyp(mutation_type: str, mutation_params: dict) -> Hypothesis:
    return Hypothesis(
        source_plugin="test",
        property_id="PROP-001",
        statement="test",
        required_experiments=[
            ExperimentSpec(
                mutation_type=mutation_type,
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params=mutation_params,
                description="test",
            )
        ],
    )


def _model_with_roles(*role_names: str) -> ApplicationModelData:
    return ApplicationModelData(
        roles=[RoleNode(name=r) for r in role_names],
    )


# ── RequestSelector tests ─────────────────────────────────────────────────────


def test_identity_swap_two_roles_same_endpoint() -> None:
    selector = RequestSelector()
    corpus = _corpus(
        "/api/users/{id_0}",
        [("user_a", "http://t.test/api/users/1"), ("user_b", "http://t.test/api/users/2")],
    )
    model = _model_with_roles("user_a", "user_b")
    hyp = _hyp("identity_swap", {})

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    assert len(plans) == 1
    p = plans[0]
    assert p.mutation_type == "identity_swap"
    assert p.baseline_role == "user_a"
    assert p.target_role == "user_b"
    assert "users/1" in p.baseline_request.url


def test_identity_swap_no_plans_with_one_role() -> None:
    selector = RequestSelector()
    corpus = _corpus("/api/users/{id_0}", [("user_a", "http://t.test/api/users/1")])
    model = _model_with_roles("user_a")
    hyp = _hyp("identity_swap", {})

    plans = selector.select_for_hypothesis(hyp, model, corpus)
    assert plans == []


def test_object_ref_change_cross_user() -> None:
    selector = RequestSelector()
    corpus = _corpus(
        "/api/users/{id_0}",
        [("user_a", "http://t.test/api/users/1"), ("user_b", "http://t.test/api/users/2")],
    )
    model = _model_with_roles("user_a", "user_b")
    hyp = _hyp("object_ref_change", {"parameter_name": "path_0", "parameter_location": "path"})

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    assert len(plans) >= 1
    plan = next(p for p in plans if p.baseline_role == "user_a")
    assert plan.mutated_value == "2"
    assert plan.mutated_param_name == "path_0"


def test_object_ref_change_sequential_fallback() -> None:
    selector = RequestSelector()
    corpus = _corpus("/api/users/{id_0}", [("user_a", "http://t.test/api/users/5")])
    model = _model_with_roles("user_a")
    hyp = _hyp("object_ref_change", {"parameter_name": "path_0", "parameter_location": "path"})

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    # Multi-probe fallback: generates up to 3 plans from a candidate set
    assert len(plans) >= 1
    assert len(plans) <= 3
    values = [p.mutated_value for p in plans]
    assert "5" not in values  # original value excluded
    # All probes are positive integers
    assert all(int(v) > 0 for v in values)
    assert all(p.baseline_role == "user_a" for p in plans)


def test_privilege_escalation_plan() -> None:
    selector = RequestSelector()
    corpus = {"/api/admin": [("admin", _req("http://t.test/api/admin"))]}
    model = _model_with_roles("admin", "user_a")
    hyp = _hyp(
        "privilege_escalation",
        {"endpoint_path": "/api/admin", "target_role": "user_a"},
    )

    plans = selector.select_for_hypothesis(hyp, model, corpus)

    assert len(plans) == 1
    p = plans[0]
    assert p.mutation_type == "privilege_escalation"
    assert p.target_role == "user_a"
    assert "/api/admin" in p.baseline_request.url


def test_no_plans_when_corpus_empty() -> None:
    selector = RequestSelector()
    model = _model_with_roles("user_a", "user_b")
    hyp = _hyp("identity_swap", {})

    plans = selector.select_for_hypothesis(hyp, model, {})
    assert plans == []


def test_privilege_escalation_no_plans_when_endpoint_not_in_corpus() -> None:
    selector = RequestSelector()
    corpus = {"/api/users": [("user_a", _req("http://t.test/api/users"))]}
    model = _model_with_roles("admin", "user_a")
    hyp = _hyp(
        "privilege_escalation",
        {"endpoint_path": "/api/admin", "target_role": "user_a"},
    )

    plans = selector.select_for_hypothesis(hyp, model, corpus)
    assert plans == []


# ── ApplicationModel corpus tests ─────────────────────────────────────────────


def _obs(url: str, role: str, response_body: dict | None = None) -> RawObservation:
    return RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url=url),
        response=NormalizedResponse(
            status_code=200,
            body=response_body or {"id": 1},
            content_type="application/json",
        ),
        session_id="sess-test",
        tags=[f"role:{role}"],
    )


@pytest.mark.asyncio
async def test_corpus_empty_for_new_model() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    assert model.get_all_corpus() == {}


@pytest.mark.asyncio
async def test_corpus_populated_by_observations() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    obs = _obs("http://t.test/api/users/1", "user_a")
    await bus.emit(OBSERVATION_RAW, obs.model_dump(), source="test")
    await bus.drain()

    corpus = model.get_all_corpus()
    assert "/api/users/{id_0}" in corpus
    entries = corpus["/api/users/{id_0}"]
    assert len(entries) == 1
    assert entries[0][0] == "user_a"
    assert "users/1" in entries[0][1].url


@pytest.mark.asyncio
async def test_model_confidence_zero_for_empty_model() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    assert model.model_confidence == pytest.approx(0.0)
    assert model.is_ready is False


@pytest.mark.asyncio
async def test_model_confidence_increases_with_endpoints_and_roles() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    # One endpoint, one role → partial coverage
    obs1 = _obs("http://t.test/api/users/1", "user_a")
    await bus.emit(OBSERVATION_RAW, obs1.model_dump(), source="test")
    await bus.drain()
    conf1 = model.model_confidence
    assert conf1 > 0.0

    # Add second role → role_coverage jumps to 1.0
    obs2 = _obs("http://t.test/api/users/2", "user_b")
    await bus.emit(OBSERVATION_RAW, obs2.model_dump(), source="test")
    await bus.drain()
    conf2 = model.model_confidence
    assert conf2 > conf1


@pytest.mark.asyncio
async def test_is_ready_true_with_sufficient_coverage() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    for i in range(3):
        obs = _obs(f"http://t.test/api/ep{i}", "user_a")
        await bus.emit(OBSERVATION_RAW, obs.model_dump(), source="test")
    obs_b = _obs("http://t.test/api/ep0", "user_b")
    await bus.emit(OBSERVATION_RAW, obs_b.model_dump(), source="test")
    await bus.drain()

    # 3 endpoints + 2 roles should push confidence above 0.3
    assert model.is_ready is True
