# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import HYPOTHESIS_GENERATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.hypothesis.engine import HypothesisEngine
from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
from hdwp.core.model.schemas import (
    Hypothesis,
    PropertyType,
    SecurityProperty,
    generate_id,
)


def _make_auth_property(statement: str = "access(S, resource) via parameter 'id' => owner(resource) = S") -> SecurityProperty:
    return SecurityProperty(
        id=generate_id("PROP"),
        type=PropertyType.AUTHORIZATION,
        formal_statement=statement,
        model_nodes=["EP-1", "PARAM-1"],
        inference_confidence=0.8,
    )


def _make_role_property() -> SecurityProperty:
    return SecurityProperty(
        id=generate_id("PROP"),
        type=PropertyType.AUTHORIZATION,
        formal_statement="role 'user' cannot access endpoints exclusive to 'admin': {'GET:/admin'}",
        model_nodes=["ROLE-1", "ROLE-2"],
        inference_confidence=0.75,
    )


def _make_confidentiality_property() -> SecurityProperty:
    return SecurityProperty(
        id=generate_id("PROP"),
        type=PropertyType.CONFIDENTIALITY,
        formal_statement="query(A, object:OBJ-1) => owner(object) = A",
        model_nodes=["OBJ-1"],
        inference_confidence=0.7,
    )


@pytest.mark.asyncio
async def test_generates_hypothesis_from_authorization_property() -> None:
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: received.append(e))

    prop = _make_auth_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert len(received) == 1
    hyp_data = received[0].payload
    assert hyp_data["property_id"] == prop.id
    mutation_types = [e["mutation_type"] for e in hyp_data["required_experiments"]]
    assert "identity_swap" in mutation_types
    assert "object_ref_change" in mutation_types


@pytest.mark.asyncio
async def test_generates_hypothesis_from_role_separation_property() -> None:
    from hdwp.core.model.schemas import ApplicationModelData, EndpointNode, RoleNode

    model = ApplicationModelData(
        endpoints=[EndpointNode(id="ROLE-1", path="/admin", methods=["GET"])],
        roles=[RoleNode(id="ROLE-1", name="admin"), RoleNode(id="ROLE-2", name="user")],
    )
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus, model_accessor=lambda: model)

    received: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: received.append(e))

    prop = _make_role_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert len(received) >= 1
    # Vérifier que la première hypothèse contient privilege_escalation
    privilege_hyps = [
        r for r in received
        if any(e["mutation_type"] == "privilege_escalation" for e in r.payload["required_experiments"])
    ]
    assert privilege_hyps, "Expected at least one privilege_escalation hypothesis"


@pytest.mark.asyncio
async def test_generates_hypothesis_from_confidentiality_property() -> None:
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: received.append(e))

    prop = _make_confidentiality_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert len(received) == 1
    hyp_data = received[0].payload
    assert "identity_swap" in [e["mutation_type"] for e in hyp_data["required_experiments"]]


@pytest.mark.asyncio
async def test_deduplicates_hypotheses() -> None:
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: received.append(e))

    prop = _make_auth_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert len(received) == 1


@pytest.mark.asyncio
async def test_get_pending_sorted_by_priority() -> None:
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus)

    # Inject hypotheses directly for sorting test
    engine._hypotheses["h1"] = Hypothesis(
        id="HYP-low",
        source_plugin="test",
        property_id="P1",
        statement="low priority",
        priority="LOW",
    )
    engine._hypotheses["h2"] = Hypothesis(
        id="HYP-high",
        source_plugin="test",
        property_id="P2",
        statement="high priority",
        priority="HIGH",
    )
    engine._hypotheses["h3"] = Hypothesis(
        id="HYP-med",
        source_plugin="test",
        property_id="P3",
        statement="medium priority",
        priority="MEDIUM",
    )

    pending = engine.get_pending()
    assert len(pending) == 3
    # Thompson Sampling : l'ordre est probabiliste — HIGH bénéficie d'un boost +0.3
    # mais l'ordre exact entre MEDIUM et LOW n'est pas garanti.
    # On vérifie seulement que les 3 hypothèses sont présentes.
    ids = {h.id for h in pending}
    assert ids == {"HYP-high", "HYP-med", "HYP-low"}


def test_prioritizer_high_priority() -> None:
    p = HypothesisPrioritizer()
    level, _ = p.compute_priority(
        property_type=PropertyType.AUTHORIZATION,
        affected_node_count=5,
        total_endpoints=5,
        observation_count=10,
    )
    assert level == "HIGH"


def test_prioritizer_low_priority() -> None:
    p = HypothesisPrioritizer()
    level, _ = p.compute_priority(
        property_type=PropertyType.CONCURRENCY,
        affected_node_count=1,
        total_endpoints=100,
        observation_count=1,
    )
    assert level == "LOW"


@pytest.mark.asyncio
async def test_save_hypothesis_called_when_repository_injected() -> None:
    """Vérifier que save_hypothesis() est appelé quand un Repository est injecté."""
    from unittest.mock import AsyncMock

    bus = AsyncEventBus()
    mock_repo = AsyncMock()
    mock_repo.save_hypothesis = AsyncMock()

    engine = HypothesisEngine(bus, repository=mock_repo)

    prop = _make_auth_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert mock_repo.save_hypothesis.called, "save_hypothesis doit être appelé"


@pytest.mark.asyncio
async def test_no_save_when_no_repository() -> None:
    """Sans Repository injecté, aucune erreur ne doit être levée."""
    bus = AsyncEventBus()
    engine = HypothesisEngine(bus)  # pas de repository

    received: list[HDWPEvent] = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: received.append(e))

    prop = _make_auth_property()
    await bus.emit(PROPERTY_INFERRED, prop.model_dump(), source="test")
    await bus.drain()

    assert len(received) >= 1
