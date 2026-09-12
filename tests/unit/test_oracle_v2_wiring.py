# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests du câblage ConfidenceModelV2 dans SemanticOracle.

Vérifie que les handlers V3 collectent correctement les signaux,
ignorent les payloads mal formés, et que les structures internes
sont cohérentes avec les clés réelles des événements V3.
"""
from __future__ import annotations

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    CROSSROLE_DIFF_CONFIRMED,
    INVARIANT_VIOLATED,
    ML_ORACLE_VERDICT,
    TEMPORAL_ANOMALY_DETECTED,
    HDWPEvent,
)
from hdwp.core.oracle.engine import SemanticOracle


class _MockRepository:
    async def save_finding(self, f: object) -> None: pass
    async def save_diff(self, d: object) -> None: pass
    async def update_hypothesis_status(self, id: str, status: str, conf: float) -> None: pass
    async def save_experiment(self, e: object) -> None: pass


def _make_oracle() -> tuple[SemanticOracle, AsyncEventBus, list[HDWPEvent]]:
    bus = AsyncEventBus()
    captured: list[HDWPEvent] = []
    bus.on(ML_ORACLE_VERDICT, lambda e: captured.append(e))
    oracle = SemanticOracle(bus=bus, repository=_MockRepository())
    return oracle, bus, captured


@pytest.mark.asyncio
async def test_temporal_signal_stored_with_hyp_id():
    oracle, bus, _ = _make_oracle()
    await bus.emit(
        TEMPORAL_ANOMALY_DETECTED,
        {"hypothesis_id": "HYP-001", "escalation_level": 1},
        source="test",
    )
    await bus.drain()
    assert oracle._temporal_signals.get("HYP-001") == pytest.approx(2 / 3, abs=1e-4)


@pytest.mark.asyncio
async def test_temporal_signal_takes_max():
    oracle, bus, _ = _make_oracle()
    await bus.emit(TEMPORAL_ANOMALY_DETECTED, {"hypothesis_id": "HYP-001", "escalation_level": 0}, source="test")
    await bus.emit(TEMPORAL_ANOMALY_DETECTED, {"hypothesis_id": "HYP-001", "escalation_level": 2}, source="test")
    await bus.drain()
    assert oracle._temporal_signals["HYP-001"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_temporal_signal_ignored_when_no_hyp_id():
    oracle, bus, _ = _make_oracle()
    await bus.emit(TEMPORAL_ANOMALY_DETECTED, {"hypothesis_id": "", "escalation_level": 2}, source="test")
    await bus.drain()
    assert len(oracle._temporal_signals) == 0


@pytest.mark.asyncio
async def test_temporal_handler_ignores_non_dict_payload():
    oracle, bus, _ = _make_oracle()
    await bus.emit(TEMPORAL_ANOMALY_DETECTED, "not a dict", source="test")
    await bus.drain()
    assert len(oracle._temporal_signals) == 0


@pytest.mark.asyncio
async def test_crossrole_signal_stored_normalized():
    oracle, bus, _ = _make_oracle()
    # CrossRoleDiffEngine émet "endpoint_path" avec URL complète
    await bus.emit(
        CROSSROLE_DIFF_CONFIRMED,
        {"endpoint_path": "http://api.example.com/api/users/1", "confidence": 0.95},
        source="test",
    )
    await bus.drain()
    # La clé doit être normalisée en path par _extract_endpoint (urlparse.path)
    assert "/api/users/1" in oracle._crossrole_signals
    assert oracle._crossrole_signals["/api/users/1"] == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_crossrole_signal_takes_max():
    oracle, bus, _ = _make_oracle()
    await bus.emit(CROSSROLE_DIFF_CONFIRMED, {"endpoint_path": "http://x/api/users", "confidence": 0.6}, source="test")
    await bus.emit(CROSSROLE_DIFF_CONFIRMED, {"endpoint_path": "http://y/api/users", "confidence": 0.9}, source="test")
    await bus.drain()
    assert oracle._crossrole_signals["/api/users"] == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_crossrole_handler_ignores_non_dict():
    oracle, bus, _ = _make_oracle()
    await bus.emit(CROSSROLE_DIFF_CONFIRMED, None, source="test")
    await bus.drain()
    assert len(oracle._crossrole_signals) == 0


@pytest.mark.asyncio
async def test_invariant_signal_stored():
    oracle, bus, _ = _make_oracle()
    await bus.emit(INVARIANT_VIOLATED, {"endpoint_path": "/api/orders"}, source="test")
    await bus.drain()
    assert oracle._invariant_signals.get("/api/orders") == 1.0


@pytest.mark.asyncio
async def test_invariant_handler_ignores_non_dict():
    oracle, bus, _ = _make_oracle()
    await bus.emit(INVARIANT_VIOLATED, 42, source="test")
    await bus.drain()
    assert len(oracle._invariant_signals) == 0


@pytest.mark.asyncio
async def test_oracle_results_property_returns_copy():
    oracle, _, _ = _make_oracle()
    results = oracle.oracle_results
    assert isinstance(results, dict)
    # Modifier le résultat retourné ne doit pas affecter l'état interne
    results["test"] = []
    assert "test" not in oracle._results


@pytest.mark.asyncio
async def test_ml_oracle_verdict_event_in_events_module():
    """ML_ORACLE_VERDICT est dans ALL_EVENT_TYPES."""
    from hdwp.core.bus.events import ALL_EVENT_TYPES, ML_ORACLE_VERDICT
    assert ML_ORACLE_VERDICT in ALL_EVENT_TYPES
