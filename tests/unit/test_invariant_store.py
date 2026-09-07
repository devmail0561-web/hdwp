# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import INVARIANT_VIOLATED, HDWPEvent
from hdwp.core.model.invariant_store import (
    InvariantStore,
    InvariantViolation,
    LearnedInvariant,
)


class _StubBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[..., Any]]] = defaultdict(list)

    def on(self, event_type: str, handler: Callable[..., Any]) -> None:
        self._handlers[event_type].append(handler)

    async def emit(self, event: HDWPEvent) -> None:
        for h in self._handlers.get(event.type, []):
            h(event)

    async def drain(self) -> None:
        pass


def _make_bus() -> _StubBus:
    return _StubBus()


def _make_store(bus: _StubBus | None = None) -> InvariantStore:
    return InvariantStore(bus=bus)


def _learn_invariant(
    store: InvariantStore,
    endpoint: str = "/api/items/{id}",
    pattern: str = "owner_id_match",
    n: int = 6,
) -> None:
    for _ in range(n):
        store.observe(endpoint, pattern, holds=True)


def test_observe_sufficient_holds_invariant_becomes_learned() -> None:
    store = _make_store()
    for _ in range(6):
        store.observe("/api/items/{id}", "owner_id_match", holds=True)

    invariants = store.get_learned_invariants()
    assert len(invariants) == 1
    assert invariants[0].is_learned is True
    assert invariants[0].confidence == 1.0
    assert invariants[0].observation_count == 6


def test_observe_insufficient_count_invariant_not_learned() -> None:
    store = _make_store()
    for _ in range(4):
        store.observe("/api/items/{id}", "owner_id_match", holds=True)

    learned = store.get_learned_invariants()
    assert len(learned) == 0

    all_inv = store.all_invariants()
    assert len(all_inv) == 1
    assert all_inv[0].is_learned is False
    assert all_inv[0].observation_count == 4


def test_confidence_with_violations_reflects_hold_rate() -> None:
    store = _make_store()
    for _ in range(8):
        store.observe("/api/data", "field_check", holds=True)
    for _ in range(2):
        store.observe("/api/data", "field_check", holds=False)

    inv = store.all_invariants()[0]
    assert inv.observation_count == 10
    assert inv.violation_count == 2
    assert inv.confidence == 0.8


@pytest.mark.asyncio
async def test_check_violation_learned_not_holds_returns_violation_and_emits() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(INVARIANT_VIOLATED, lambda e: collected.append(e))

    store = _make_store(bus=bus)
    _learn_invariant(store, "/api/orders/{id}", "owner_id_match")

    result = await store.check_violation(
        endpoint_path="/api/orders/{id}",
        pattern_type="owner_id_match",
        holds=False,
        experiment_id="EXP-001",
        observed_value=42,
    )

    assert isinstance(result, InvariantViolation)
    assert result.invariant.endpoint_path == "/api/orders/{id}"
    assert result.experiment_id == "EXP-001"
    assert result.observed_value == 42
    assert len(collected) == 1
    assert collected[0].type == INVARIANT_VIOLATED
    assert collected[0].payload["endpoint_path"] == "/api/orders/{id}"
    assert collected[0].payload["experiment_id"] == "EXP-001"
    assert collected[0].payload["observed_value"] == "42"


@pytest.mark.asyncio
async def test_check_violation_not_yet_learned_returns_none_keeps_observing() -> None:
    store = _make_store()
    for _ in range(3):
        store.observe("/api/users/{id}", "owner_id_match", holds=True)

    result = await store.check_violation(
        endpoint_path="/api/users/{id}",
        pattern_type="owner_id_match",
        holds=False,
    )

    assert result is None
    inv = store.all_invariants()[0]
    assert inv.observation_count == 4
    assert inv.violation_count == 1


@pytest.mark.asyncio
async def test_check_violation_learned_holds_returns_none() -> None:
    store = _make_store()
    _learn_invariant(store, "/api/data", "status_check")

    result = await store.check_violation(
        endpoint_path="/api/data",
        pattern_type="status_check",
        holds=True,
    )

    assert result is None


def test_observe_owner_id_match_same_id_holds() -> None:
    store = _make_store()
    store.observe_owner_id_match(
        "/api/items/{id}", response_owner_id=7, authenticated_user_id=7
    )

    inv = store.all_invariants()[0]
    assert inv.observation_count == 1
    assert inv.violation_count == 0
    assert inv.pattern_type == "owner_id_match"


def test_observe_owner_id_match_different_id_not_holds() -> None:
    store = _make_store()
    store.observe_owner_id_match(
        "/api/items/{id}", response_owner_id=42, authenticated_user_id=7
    )

    inv = store.all_invariants()[0]
    assert inv.observation_count == 1
    assert inv.violation_count == 1


def test_observe_status_code_stable_tracks_match_and_mismatch() -> None:
    store = _make_store()
    store.observe_status_code_stable(
        "/api/health", role="user", status_code=200, expected_code=200
    )
    inv = store.all_invariants()[0]
    assert inv.violation_count == 0
    assert inv.pattern_type == "status_user_eq_200"

    store.observe_status_code_stable(
        "/api/health", role="user", status_code=403, expected_code=200
    )
    assert inv.violation_count == 1
    assert inv.observation_count == 2


def test_observe_field_presence_absent_when_expected_not_holds() -> None:
    store = _make_store()
    store.observe_field_presence(
        "/api/users/{id}", field_name="email", present=True, expected=True
    )
    inv = store.all_invariants()[0]
    assert inv.violation_count == 0
    assert inv.pattern_type == "field_email_present"

    store.observe_field_presence(
        "/api/users/{id}", field_name="email", present=False, expected=True
    )
    assert inv.violation_count == 1
    assert inv.observation_count == 2


def test_get_learned_invariants_returns_only_learned() -> None:
    store = _make_store()
    _learn_invariant(store, "/api/a", "pattern_a", n=6)
    for _ in range(2):
        store.observe("/api/b", "pattern_b", holds=True)

    learned = store.get_learned_invariants()
    assert len(learned) == 1
    assert learned[0].endpoint_path == "/api/a"


def test_get_learned_invariants_filters_by_endpoint_path() -> None:
    store = _make_store()
    _learn_invariant(store, "/api/x", "pattern_x", n=6)
    _learn_invariant(store, "/api/y", "pattern_y", n=6)

    x_only = store.get_learned_invariants(endpoint_path="/api/x")
    assert len(x_only) == 1
    assert x_only[0].endpoint_path == "/api/x"

    all_learned = store.get_learned_invariants()
    assert len(all_learned) == 2
