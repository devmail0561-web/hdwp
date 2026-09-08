# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    HYPOTHESIS_AMBIGUOUS,
    HYPOTHESIS_GENERATED,
    HYPOTHESIS_STATUS_CHANGED,
    PROPERTY_INFERRED,
    HDWPEvent,
)
from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ExperimentSpec,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    ParameterNode,
    RoleNode,
)
from hdwp.core.reasoning.layer import (
    AdaptiveSpecGenerator,
    ContextualHypothesisEngine,
    HypothesisContext,
    StrategyDepth,
    StrategySelector,
)


def _make_bus() -> AsyncEventBus:
    return AsyncEventBus()


def _make_model(
    tech_stack: list[str] | None = None,
    param_type: str = "string",
) -> ApplicationModelData:
    return ApplicationModelData(
        endpoints=[
            EndpointNode(
                id="EP-1",
                path="/api/users",
                methods=["GET"],
                parameters=["P-1"],
                roles_observed=["admin"],
            ),
        ],
        parameters=[
            ParameterNode(
                id="P-1",
                name="user_id",
                location="path",
                type_inferred=param_type,
            ),
        ],
        roles=[RoleNode(name="admin")],
        tech_stack=tech_stack or ["postgresql"],
        response_corpus={},
    )


def _make_engine(
    bus: AsyncEventBus | None = None,
    model: ApplicationModelData | None = None,
    threat_scores: dict[str, float] | None = None,
) -> ContextualHypothesisEngine:
    bus = bus or _make_bus()
    model = model or _make_model()
    scores = threat_scores or {"/api/users": 0.9}
    return ContextualHypothesisEngine(
        bus=bus,
        model_accessor=lambda: model,
        threat_model_accessor=lambda: scores,
    )


# ── StrategySelector ──────────────────────────────────────────────────────────


def test_strategy_selector_deep_for_high_threat() -> None:
    selector = StrategySelector()
    assert selector.select(0.85) == StrategyDepth.DEEP


def test_strategy_selector_standard_for_medium_threat() -> None:
    selector = StrategySelector()
    assert selector.select(0.6) == StrategyDepth.STANDARD


def test_strategy_selector_shallow_for_low_threat() -> None:
    selector = StrategySelector()
    assert selector.select(0.3) == StrategyDepth.SHALLOW


def test_strategy_selector_passive_for_minimal_threat() -> None:
    selector = StrategySelector()
    assert selector.select(0.1) == StrategyDepth.PASSIVE


# ── AdaptiveSpecGenerator ─────────────────────────────────────────────────────


def test_spec_generator_passive_returns_fewer_payloads() -> None:
    gen = AdaptiveSpecGenerator()
    ctx = HypothesisContext(parameter_type="string")
    passive = gen.generate(ctx, StrategyDepth.PASSIVE)
    deep = gen.generate(ctx, StrategyDepth.DEEP)
    assert len(passive) <= 2
    assert len(deep) > len(passive)


def test_spec_generator_db_specific_payloads_for_postgresql() -> None:
    gen = AdaptiveSpecGenerator()
    ctx = HypothesisContext(
        parameter_type="string",
        tech_stack=["postgresql"],
    )
    payloads = gen.generate(ctx, StrategyDepth.DEEP)
    assert any("pg_sleep" in p for p in payloads)


def test_spec_generator_numeric_payloads_for_integer_type() -> None:
    gen = AdaptiveSpecGenerator()
    ctx_int = HypothesisContext(parameter_type="integer")
    ctx_str = HypothesisContext(parameter_type="string")
    int_payloads = gen.generate(ctx_int, StrategyDepth.STANDARD)
    str_payloads = gen.generate(ctx_str, StrategyDepth.STANDARD)
    assert any(p.startswith("0") or p.startswith("-1") for p in int_payloads)
    assert any("'" in p or "<" in p for p in str_payloads)


# ── ContextualHypothesisEngine ────────────────────────────────────────────────


def test_get_pending_returns_only_pending() -> None:
    engine = _make_engine()
    h1 = Hypothesis(
        source_plugin="test", property_id="P1", statement="S1",
        status=HypothesisStatus.PENDING,
    )
    h2 = Hypothesis(
        source_plugin="test", property_id="P2", statement="S2",
        status=HypothesisStatus.CONFIRMED,
    )
    engine._hypotheses.extend([h1, h2])
    engine._seen_keys.add(("S1", "", ""))
    engine._seen_keys.add(("S2", "", ""))

    pending = engine.get_pending()
    assert len(pending) == 1
    assert pending[0].statement == "S1"


def test_deduplication_rejects_same_key() -> None:
    engine = _make_engine()
    spec = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url="/api/users"),
        mutation_params={"endpoint_path": "/api/users", "parameter_name": "user_id"},
    )
    h1 = Hypothesis(
        source_plugin="test", property_id="P1", statement="first",
        required_experiments=[spec],
    )
    h2 = Hypothesis(
        source_plugin="test", property_id="P2", statement="second",
        required_experiments=[spec],
    )

    assert engine._add_hypothesis(h1) is True
    assert engine._add_hypothesis(h2) is False
    assert len(engine._hypotheses) == 1


@pytest.mark.asyncio
async def test_property_inferred_generates_hypotheses() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: collected.append(e))

    _make_engine(bus=bus)

    await bus.emit(
        PROPERTY_INFERRED,
        {"type": "BOLA", "model_nodes": ["/api/users"], "id": "PROP-1"},
        source="test",
    )
    await bus.drain()

    assert len(collected) >= 1
    payload = collected[0].payload
    assert payload["source_plugin"] == "contextual_hypothesis_engine"
    assert payload["property_type"] == "BOLA"


@pytest.mark.asyncio
async def test_finding_confirmed_does_not_crash() -> None:
    bus = _make_bus()
    _make_engine(bus=bus)

    await bus.emit(
        FINDING_CONFIRMED,
        {"property_type": "BOLA", "mutation_type": "field_injection"},
        source="test",
    )
    await bus.drain()


def test_hypotheses_property_returns_copy() -> None:
    engine = _make_engine()
    h = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    engine._hypotheses.append(h)
    engine._seen_keys.add(("S1", "", ""))

    copy = engine.hypotheses
    assert copy == [h]
    copy.clear()
    assert len(engine._hypotheses) == 1


@pytest.mark.asyncio
async def test_high_threat_score_generates_high_priority() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: collected.append(e))

    _make_engine(bus=bus, threat_scores={"/api/users": 0.9})

    await bus.emit(
        PROPERTY_INFERRED,
        {"type": "BOLA", "model_nodes": ["/api/users"], "id": "PROP-2"},
        source="test",
    )
    await bus.drain()

    assert len(collected) >= 1
    assert collected[0].payload["priority"] == "HIGH"


# ── Hypothesis status sync (Bug 1 fix) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_status_updated_on_hypothesis_status_changed() -> None:
    bus = _make_bus()
    engine = _make_engine(bus=bus)
    h = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    engine._hypotheses.append(h)
    engine._seen_keys.add(("S1", "", ""))

    assert len(engine.get_pending()) == 1

    await bus.emit(
        HYPOTHESIS_STATUS_CHANGED,
        {"id": h.id, "old_status": "PENDING", "new_status": "CONFIRMED"},
        source="test",
    )
    await bus.drain()

    assert len(engine.get_pending()) == 0
    assert h.status == HypothesisStatus.CONFIRMED


@pytest.mark.asyncio
async def test_status_changed_unknown_id_is_noop() -> None:
    bus = _make_bus()
    engine = _make_engine(bus=bus)
    h = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    engine._hypotheses.append(h)

    await bus.emit(
        HYPOTHESIS_STATUS_CHANGED,
        {"id": "HYP-unknown", "old_status": "PENDING", "new_status": "CONFIRMED"},
        source="test",
    )
    await bus.drain()

    assert h.status == HypothesisStatus.PENDING


@pytest.mark.asyncio
async def test_status_changed_invalid_status_is_noop() -> None:
    bus = _make_bus()
    engine = _make_engine(bus=bus)
    h = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    engine._hypotheses.append(h)

    await bus.emit(
        HYPOTHESIS_STATUS_CHANGED,
        {"id": h.id, "old_status": "PENDING", "new_status": "BOGUS_STATUS"},
        source="test",
    )
    await bus.drain()

    assert h.status == HypothesisStatus.PENDING


@pytest.mark.asyncio
async def test_all_resolved_returns_empty_pending() -> None:
    bus = _make_bus()
    engine = _make_engine(bus=bus)
    h1 = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    h2 = Hypothesis(source_plugin="test", property_id="P2", statement="S2")
    engine._hypotheses.extend([h1, h2])

    await bus.emit(
        HYPOTHESIS_STATUS_CHANGED,
        {"id": h1.id, "old_status": "PENDING", "new_status": "CONFIRMED"},
        source="test",
    )
    await bus.emit(
        HYPOTHESIS_STATUS_CHANGED,
        {"id": h2.id, "old_status": "PENDING", "new_status": "REFUTED"},
        source="test",
    )
    await bus.drain()

    assert engine.get_pending() == []


@pytest.mark.asyncio
async def test_status_changed_non_dict_payload_is_noop() -> None:
    bus = _make_bus()
    engine = _make_engine(bus=bus)
    h = Hypothesis(source_plugin="test", property_id="P1", statement="S1")
    engine._hypotheses.append(h)
    engine._seen_keys.add(("S1", "", ""))

    await bus.emit(HYPOTHESIS_STATUS_CHANGED, None, source="test")  # type: ignore[arg-type]
    await bus.drain()

    assert h.status == HypothesisStatus.PENDING
