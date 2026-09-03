# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

import httpx

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import EXPERIMENT_RESULT, HYPOTHESIS_EXPERIMENTS_READY, HDWPEvent
from hdwp.core.context.config_schema import CredentialConfig, OptionsConfig, RoleConfig, ScopeConfig, TargetConfig
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.engine import ExperimentEngine
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.request_selector import RequestSelector
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConcreteExperimentPlan,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    RoleNode,
    EndpointNode,
)
from hdwp.core.context.config_schema import HDWPContextConfig
from tests.fixtures.mock_server import AsyncVulnerableAppTransport


def _make_context(base_url: str = "http://test") -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url=base_url, name="Test"),
        scope=ScopeConfig(include=[f"{base_url}/*"]),
        options=OptionsConfig(allow_write=False, max_requests_per_minute=6000),
    )
    return EngineContext(config=config, base_url=base_url, session_id="S-test")


def _make_roles() -> list[RoleConfig]:
    return [
        RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="token_alice")),
        RoleConfig(name="user_b", credentials=CredentialConfig(type="bearer", token="token_bob")),
    ]


def _make_session_manager(roles: list[RoleConfig]) -> SessionManager:
    sm = SessionManager(roles)
    for role in roles:
        # Attach mock transport to each client
        sm._clients[role.name] = httpx.AsyncClient(  # noqa: SLF001
            transport=AsyncVulnerableAppTransport(),
            base_url="http://test",
        )
    return sm


def _make_engine(
    bus: AsyncEventBus,
    context: EngineContext,
    session_manager: SessionManager,
    model: ApplicationModelData,
    corpus: dict,
) -> ExperimentEngine:
    scope_guard = ScopeGuard(context)
    rate_limiter = TokenBucket.from_rpm(6000)
    return ExperimentEngine(
        bus=bus,
        scope_guard=scope_guard,
        session_manager=session_manager,
        rate_limiter=rate_limiter,
        model_accessor=lambda: model,
        corpus_accessor=lambda: corpus,
    )


def _make_hypothesis_with_plans(
    model: ApplicationModelData,
    corpus: dict,
) -> tuple[Hypothesis, list[ConcreteExperimentPlan]]:
    """Create a hypothesis whose RequestSelector will find plans in the corpus."""
    from hdwp.core.model.schemas import generate_id
    spec = ExperimentSpec(
        mutation_type="identity_swap",
        base_request=NormalizedRequest(method="GET", url=""),
        mutation_params={},
        description="test identity_swap",
    )
    hyp = Hypothesis(
        source_plugin="test",
        property_id="PROP-test",
        statement="test hypothesis",
        priority="HIGH",
        priority_rationale="test",
        required_experiments=[spec],
    )
    return hyp, RequestSelector().select_for_hypothesis(hyp, model, corpus)


def _build_model_and_corpus() -> tuple[ApplicationModelData, dict]:
    """Build a model and corpus matching the mock server's /api/users/1 endpoint."""
    req_alice = NormalizedRequest(
        method="GET",
        url="http://test/api/users/1",
        headers={"Authorization": "Bearer token_alice"},
        body=None,
        query_params={},
        path_params={},
    )
    req_bob = NormalizedRequest(
        method="GET",
        url="http://test/api/users/2",
        headers={"Authorization": "Bearer token_bob"},
        body=None,
        query_params={},
        path_params={},
    )
    corpus = {
        "/api/users/{id_0}": [
            ("user_a", req_alice),
            ("user_b", req_bob),
        ]
    }
    model = ApplicationModelData(
        endpoints=[EndpointNode(path="/api/users/{id_0}", methods=["GET"])],
        parameters=[],
        objects=[],
        roles=[RoleNode(name="user_a"), RoleNode(name="user_b")],
        relations=[],
        last_updated="",
    )
    return model, corpus


@pytest.mark.asyncio
async def test_run_pending_emits_experiment_results() -> None:
    bus = AsyncEventBus()
    model, corpus = _build_model_and_corpus()
    roles = _make_roles()
    sm = _make_session_manager(roles)
    ctx = _make_context()
    engine = _make_engine(bus, ctx, sm, model, corpus)

    received: list[HDWPEvent] = []
    bus.on(EXPERIMENT_RESULT, lambda e: received.append(e))

    hyp, _ = _make_hypothesis_with_plans(model, corpus)
    await engine.run_pending([hyp])
    await bus.drain()

    # baseline + mutation + replay = 3 per plan (1 plan for identity_swap)
    assert len(received) >= 2


@pytest.mark.asyncio
async def test_replay_has_replayed_from_set() -> None:
    bus = AsyncEventBus()
    model, corpus = _build_model_and_corpus()
    roles = _make_roles()
    sm = _make_session_manager(roles)
    ctx = _make_context()
    engine = _make_engine(bus, ctx, sm, model, corpus)

    results: list[dict] = []
    bus.on(EXPERIMENT_RESULT, lambda e: results.append(e.payload))

    hyp, _ = _make_hypothesis_with_plans(model, corpus)
    await engine.run_pending([hyp])
    await bus.drain()

    replays = [r for r in results if r.get("replayed_from") is not None]
    assert len(replays) >= 1


@pytest.mark.asyncio
async def test_experiments_ready_emitted_after_batch() -> None:
    bus = AsyncEventBus()
    model, corpus = _build_model_and_corpus()
    roles = _make_roles()
    sm = _make_session_manager(roles)
    ctx = _make_context()
    engine = _make_engine(bus, ctx, sm, model, corpus)

    ready_events: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_EXPERIMENTS_READY, lambda e: ready_events.append(e))

    hyp, _ = _make_hypothesis_with_plans(model, corpus)
    await engine.run_pending([hyp])
    await bus.drain()

    assert len(ready_events) == 1
    payload = ready_events[0].payload
    assert payload["hypothesis_id"] == hyp.id
    assert payload["baseline_id"] is not None
    assert len(payload["experiment_ids"]) >= 1


@pytest.mark.asyncio
async def test_scope_blocked_plan_skipped() -> None:
    """If scope blocks the mutation, the plan is skipped without crashing."""
    from hdwp.core.context.config_schema import HDWPContextConfig, ScopeConfig, TargetConfig, OptionsConfig
    config = HDWPContextConfig(
        target=TargetConfig(base_url="http://other", name="Other"),
        scope=ScopeConfig(include=["http://other/*"]),  # test.* is out of scope
        options=OptionsConfig(max_requests_per_minute=6000),
    )
    ctx = EngineContext(config=config, base_url="http://other", session_id="S-test")
    bus = AsyncEventBus()
    model, corpus = _build_model_and_corpus()
    roles = _make_roles()
    sm = _make_session_manager(roles)
    scope_guard = ScopeGuard(ctx)
    rate_limiter = TokenBucket.from_rpm(6000)
    engine = ExperimentEngine(
        bus=bus,
        scope_guard=scope_guard,
        session_manager=sm,
        rate_limiter=rate_limiter,
        model_accessor=lambda: model,
        corpus_accessor=lambda: corpus,
    )

    results: list[HDWPEvent] = []
    bus.on(EXPERIMENT_RESULT, lambda e: results.append(e))

    hyp, _ = _make_hypothesis_with_plans(model, corpus)
    # Should not raise even though mutation is out of scope
    await engine.run_pending([hyp])
    await bus.drain()

    # Baseline may still be emitted, but mutation results are skipped
    mutation_results = [r for r in results if r.payload.get("replayed_from") is None]
    # At most 1 baseline result; no mutation result
    assert len(mutation_results) <= 1


@pytest.mark.asyncio
async def test_http_failure_returns_status_zero() -> None:
    """Network failures produce an ExperimentResult with status_code=0, not a crash."""
    bus = AsyncEventBus()
    model, corpus = _build_model_and_corpus()
    roles = _make_roles()

    # Transport that always fails
    class _FailTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated failure")

    sm = SessionManager(roles)
    for role in roles:
        sm._clients[role.name] = httpx.AsyncClient(  # noqa: SLF001
            transport=_FailTransport(),
            base_url="http://test",
        )

    ctx = _make_context()
    engine = _make_engine(bus, ctx, sm, model, corpus)

    results: list[dict] = []
    bus.on(EXPERIMENT_RESULT, lambda e: results.append(e.payload))

    hyp, _ = _make_hypothesis_with_plans(model, corpus)
    await engine.run_pending([hyp])
    await bus.drain()

    assert len(results) >= 1
    for r in results:
        resp = r["response_received"]
        assert resp["status_code"] == 0
