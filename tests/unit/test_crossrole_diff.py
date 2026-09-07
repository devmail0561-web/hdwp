# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import pytest

from hdwp.core.bus.events import (
    CROSSROLE_DIFF_CONFIRMED,
    EXPERIMENT_RESULT,
    HDWPEvent,
)
from hdwp.core.oracle.crossrole_diff import CrossRoleDiffEngine, DiffType, _is_masked


class FakeBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list] = {}
        self.emitted: list[HDWPEvent] = []

    def on(self, event_type: str, handler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    async def emit(self, event_or_type, payload=None, source: str = "") -> None:
        if isinstance(event_or_type, HDWPEvent):
            event = event_or_type
        else:
            event = HDWPEvent(type=event_or_type, source=source, payload=payload)
        self.emitted.append(event)
        for handler in self._handlers.get(event.type, []):
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)

    async def drain(self) -> None:
        pass


def _make_bus() -> FakeBus:
    return FakeBus()


def _make_engine(bus: FakeBus | None = None) -> CrossRoleDiffEngine:
    if bus is None:
        bus = _make_bus()
    return CrossRoleDiffEngine(bus=bus)


def test_structural_diff_sensitive_field_leaked_returns_09_confidence() -> None:
    engine = _make_engine()
    body_a = {"name": "Alice", "secret": "s3cr3t"}
    body_b = {"name": "Alice"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    assert len(results) == 1
    assert results[0].diff_type == DiffType.STRUCTURAL
    assert results[0].confidence == 0.9
    assert "secret" in results[0].details["sensitive_leaked"]


def test_structural_diff_non_sensitive_extra_fields_returns_07_confidence() -> None:
    engine = _make_engine()
    body_a = {"name": "Alice", "debug_flag": True, "trace_id": "xyz"}
    body_b = {"name": "Alice"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    assert len(results) == 1
    assert results[0].diff_type == DiffType.STRUCTURAL
    assert results[0].confidence == 0.7
    assert results[0].details["sensitive_leaked"] == []


def test_identity_diff_owner_id_mismatch_returns_095_confidence() -> None:
    engine = _make_engine()
    body_a = {"owner_id": 1, "data": "same"}
    body_b = {"owner_id": 2, "data": "same"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    assert len(results) == 1
    assert results[0].diff_type == DiffType.IDENTITY
    assert results[0].confidence == 0.95
    assert "owner_id" in results[0].details["mismatches"]


def test_value_diff_ssn_masked_in_role_b_returns_value_diff() -> None:
    engine = _make_engine()
    body_a = {"ssn": "123-45-6789"}
    body_b = {"ssn": "***-**-****"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    assert len(results) == 1
    assert results[0].diff_type == DiffType.VALUE
    assert "ssn" in results[0].details["masked_fields"]


def test_compare_direct_identical_bodies_returns_empty_list() -> None:
    engine = _make_engine()
    body = {"name": "Alice", "role": "user", "age": 30}
    results = engine.compare_direct("/api/u/1", "admin", body, "user", body)
    assert results == []


def test_compare_direct_returns_multiple_diff_types_simultaneously() -> None:
    engine = _make_engine()
    body_a = {"owner_id": 1, "secret": "s3cr3t", "name": "Alice"}
    body_b = {"owner_id": 2, "name": "Alice"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    diff_types = {r.diff_type for r in results}
    assert DiffType.STRUCTURAL in diff_types
    assert DiffType.IDENTITY in diff_types
    assert len(results) == 2


def test_is_masked_star_pattern_returns_true() -> None:
    assert _is_masked("***-**-****") is True


def test_is_masked_plain_string_returns_false() -> None:
    assert _is_masked("hello") is False


def test_is_masked_short_string_returns_false() -> None:
    assert _is_masked("ab") is False


def test_structural_diff_details_contain_correct_field_name_lists() -> None:
    engine = _make_engine()
    body_a = {"name": "Alice", "password": "hunter2"}
    body_b = {"name": "Alice"}
    results = engine.compare_direct("/api/u/1", "admin", body_a, "user", body_b)
    assert len(results) == 1
    assert results[0].details["sensitive_leaked"] == ["password"]
    assert results[0].details["extra_in_a"] == ["password"]
    assert results[0].details["extra_in_b"] == []


@pytest.mark.asyncio
async def test_bus_emits_crossrole_diff_confirmed_on_experiment_results_for_different_roles() -> None:
    bus = _make_bus()
    engine = CrossRoleDiffEngine(bus=bus)
    confirmed: list[HDWPEvent] = []
    bus.on(CROSSROLE_DIFF_CONFIRMED, lambda e: confirmed.append(e))

    payload_admin = {
        "replayed_from": "admin",
        "request_sent": {"url": "/api/items/1"},
        "response_received": {"body": {"id": 1, "secret": "s3cr3t"}},
    }
    payload_user = {
        "replayed_from": "user",
        "request_sent": {"url": "/api/items/1"},
        "response_received": {"body": {"id": 1}},
    }

    await bus.emit(EXPERIMENT_RESULT, payload_admin)
    await bus.emit(EXPERIMENT_RESULT, payload_user)

    assert len(confirmed) >= 1
    assert confirmed[0].payload["diff_type"] == DiffType.STRUCTURAL.value
