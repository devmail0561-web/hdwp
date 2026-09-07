# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import inspect
import math
from collections import defaultdict
from typing import Any, Callable

import pytest

from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    HDWPEvent,
    TEMPORAL_ANOMALY_DETECTED,
)
from hdwp.core.oracle.temporal_detector import (
    MIN_SAMPLES,
    TemporalAnomalyDetector,
    TimingBaseline,
)


class _StubBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[..., Any]]] = defaultdict(list)

    def on(self, event_type: str, handler: Callable[..., Any]) -> None:
        self._handlers[event_type].append(handler)

    async def emit(self, event: HDWPEvent) -> None:
        for h in self._handlers.get(event.type, []):
            result = h(event)
            if inspect.isawaitable(result):
                await result

    async def drain(self) -> None:
        pass


def _make_bus() -> _StubBus:
    return _StubBus()


def _make_event(
    timing_ms: float = 100.0,
    url: str = "http://test/api/users",
    hypothesis_id: str = "HYP-123",
) -> HDWPEvent:
    return HDWPEvent(
        type=EXPERIMENT_RESULT,
        source="test",
        payload={
            "timing_ms": timing_ms,
            "request_sent": {"url": url},
            "hypothesis_id": hypothesis_id,
        },
    )


BASELINE_TIMINGS = [100.0, 120.0, 110.0, 130.0, 115.0]


async def _build_baseline(
    bus: _StubBus,
    url: str = "http://test/api/users",
) -> None:
    for t in BASELINE_TIMINGS:
        await bus.emit(_make_event(timing_ms=t, url=url))


def test_timing_baseline_known_data_correct_stats() -> None:
    bl = TimingBaseline()
    for v in [100.0, 200.0, 300.0, 400.0, 500.0]:
        bl.add(v)

    assert bl.count == 5
    assert bl.mean == 300.0
    assert bl.stddev == pytest.approx(math.sqrt(25000), abs=1e-6)
    assert bl.p95 == 500.0


def test_timing_baseline_threshold_equals_p95_plus_2_stddev() -> None:
    bl = TimingBaseline()
    for v in [100.0, 200.0, 300.0, 400.0, 500.0]:
        bl.add(v)

    expected = bl.p95 + 2.0 * bl.stddev
    assert bl.threshold == pytest.approx(expected, abs=1e-6)


def test_timing_baseline_empty_returns_zero_for_all_stats() -> None:
    bl = TimingBaseline()

    assert bl.count == 0
    assert bl.mean == 0.0
    assert bl.stddev == 0.0
    assert bl.p95 == 0.0
    assert bl.threshold == 0.0


def test_timing_baseline_single_sample_stddev_zero() -> None:
    bl = TimingBaseline()
    bl.add(42.0)

    assert bl.count == 1
    assert bl.mean == 42.0
    assert bl.stddev == 0.0
    assert bl.p95 == 42.0


@pytest.mark.asyncio
async def test_detector_first_samples_baseline_building_no_anomaly() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(TEMPORAL_ANOMALY_DETECTED, lambda e: collected.append(e))

    detector = TemporalAnomalyDetector(bus=bus)

    for t in BASELINE_TIMINGS:
        await bus.emit(_make_event(timing_ms=t))

    assert len(collected) == 0
    bl = detector.get_baseline("http://test/api/users")
    assert bl is not None
    assert bl.count == MIN_SAMPLES


@pytest.mark.asyncio
async def test_detector_normal_timing_after_baseline_no_anomaly() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(TEMPORAL_ANOMALY_DETECTED, lambda e: collected.append(e))

    detector = TemporalAnomalyDetector(bus=bus)
    await _build_baseline(bus)

    await bus.emit(_make_event(timing_ms=140.0))

    assert len(collected) == 0


@pytest.mark.asyncio
async def test_detector_slow_timing_after_baseline_emits_anomaly() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(TEMPORAL_ANOMALY_DETECTED, lambda e: collected.append(e))

    detector = TemporalAnomalyDetector(bus=bus)
    await _build_baseline(bus)

    await bus.emit(_make_event(timing_ms=999.0))

    assert len(collected) == 1
    assert collected[0].type == TEMPORAL_ANOMALY_DETECTED


@pytest.mark.asyncio
async def test_detector_escalation_first_zero_second_one_third_two() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(TEMPORAL_ANOMALY_DETECTED, lambda e: collected.append(e))

    detector = TemporalAnomalyDetector(bus=bus)
    await _build_baseline(bus)

    for _ in range(3):
        await bus.emit(_make_event(timing_ms=999.0))

    assert len(collected) == 3
    assert collected[0].payload["escalation_level"] == 0
    assert collected[1].payload["escalation_level"] == 1
    assert collected[2].payload["escalation_level"] == 2


@pytest.mark.asyncio
async def test_detector_anomaly_payload_contains_all_fields() -> None:
    bus = _make_bus()
    collected: list[HDWPEvent] = []
    bus.on(TEMPORAL_ANOMALY_DETECTED, lambda e: collected.append(e))

    detector = TemporalAnomalyDetector(bus=bus)
    await _build_baseline(bus)

    await bus.emit(_make_event(timing_ms=999.0, hypothesis_id="HYP-42"))

    assert len(collected) == 1
    payload = collected[0].payload
    assert payload["endpoint_path"] == "http://test/api/users"
    assert payload["timing_ms"] == 999.0
    assert payload["threshold"] == pytest.approx(
        130.0 + 2.0 * math.sqrt(125.0), abs=0.01
    )
    assert payload["suggested_delay"] == 1.0
    assert payload["hypothesis_id"] == "HYP-42"
    assert payload["escalation_level"] == 0
    assert payload["baseline_p95"] == pytest.approx(130.0)


def test_detector_get_baseline_unknown_endpoint_returns_none() -> None:
    bus = _make_bus()
    detector = TemporalAnomalyDetector(bus=bus)

    assert detector.get_baseline("http://unknown/path") is None


def test_detector_get_anomaly_count_unknown_endpoint_returns_zero() -> None:
    bus = _make_bus()
    detector = TemporalAnomalyDetector(bus=bus)

    assert detector.get_anomaly_count("http://unknown/path") == 0


@pytest.mark.asyncio
async def test_detector_normal_timing_after_baseline_grows_baseline() -> None:
    bus = _make_bus()
    detector = TemporalAnomalyDetector(bus=bus)
    await _build_baseline(bus)

    bl = detector.get_baseline("http://test/api/users")
    assert bl is not None
    assert bl.count == MIN_SAMPLES

    await bus.emit(_make_event(timing_ms=140.0))

    assert bl.count == MIN_SAMPLES + 1
