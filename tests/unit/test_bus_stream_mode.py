# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW, MODEL_UPDATED, HDWPEvent


@pytest.fixture
def bus() -> AsyncEventBus:
    return AsyncEventBus(max_history=50)


@pytest.mark.asyncio
async def test_stream_handler_fires_immediately_without_drain(bus: AsyncEventBus) -> None:
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler, mode="stream")
    await bus.emit(OBSERVATION_RAW, {"val": 1}, source="test")

    assert len(received) == 1
    assert received[0].payload == {"val": 1}


@pytest.mark.asyncio
async def test_batch_handler_requires_drain(bus: AsyncEventBus) -> None:
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    await bus.emit(OBSERVATION_RAW, "batch_payload", source="test")

    assert len(received) == 0

    await bus.drain()

    assert len(received) == 1
    assert received[0].payload == "batch_payload"


@pytest.mark.asyncio
async def test_stream_and_batch_coexist(bus: AsyncEventBus) -> None:
    stream_events: list[HDWPEvent] = []
    batch_events: list[HDWPEvent] = []

    async def stream_handler(event: HDWPEvent) -> None:
        stream_events.append(event)

    async def batch_handler(event: HDWPEvent) -> None:
        batch_events.append(event)

    bus.on(OBSERVATION_RAW, stream_handler, mode="stream")
    bus.on(OBSERVATION_RAW, batch_handler)

    await bus.emit(OBSERVATION_RAW, "coexist", source="test")

    assert len(stream_events) == 1
    assert len(batch_events) == 0

    await bus.drain()

    assert len(stream_events) == 1
    assert len(batch_events) == 1
    assert stream_events[0].payload == "coexist"
    assert batch_events[0].payload == "coexist"


@pytest.mark.asyncio
async def test_multiple_stream_handlers_fire_in_order(bus: AsyncEventBus) -> None:
    order: list[str] = []

    async def handler_a(event: HDWPEvent) -> None:
        order.append("A")

    async def handler_b(event: HDWPEvent) -> None:
        order.append("B")

    async def handler_c(event: HDWPEvent) -> None:
        order.append("C")

    bus.on(OBSERVATION_RAW, handler_a, mode="stream")
    bus.on(OBSERVATION_RAW, handler_b, mode="stream")
    bus.on(OBSERVATION_RAW, handler_c, mode="stream")

    await bus.emit(OBSERVATION_RAW, "order_test", source="test")

    assert order == ["A", "B", "C"]


@pytest.mark.asyncio
async def test_stream_handler_exception_does_not_block_others(bus: AsyncEventBus) -> None:
    received: list[str] = []

    async def failing_handler(event: HDWPEvent) -> None:
        raise ValueError("boom")

    async def good_handler(event: HDWPEvent) -> None:
        received.append("ok")

    bus.on(OBSERVATION_RAW, failing_handler, mode="stream")
    bus.on(OBSERVATION_RAW, good_handler, mode="stream")

    await bus.emit(OBSERVATION_RAW, "error_test", source="test")

    assert received == ["ok"]


@pytest.mark.asyncio
async def test_stream_handler_receives_correct_event(bus: AsyncEventBus) -> None:
    captured: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        captured.append(event)

    bus.on(OBSERVATION_RAW, handler, mode="stream")
    await bus.emit(OBSERVATION_RAW, {"key": "value"}, source="my_source")

    assert len(captured) == 1
    evt = captured[0]
    assert evt.type == OBSERVATION_RAW
    assert evt.payload == {"key": "value"}
    assert evt.source == "my_source"
    assert evt.timestamp


@pytest.mark.asyncio
async def test_default_mode_is_batch(bus: AsyncEventBus) -> None:
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    await bus.emit(OBSERVATION_RAW, "default_mode", source="test")

    assert len(received) == 0

    await bus.drain()
    assert len(received) == 1


@pytest.mark.asyncio
async def test_stream_handler_isolated_by_event_type(bus: AsyncEventBus) -> None:
    obs_events: list[HDWPEvent] = []
    model_events: list[HDWPEvent] = []

    async def obs_handler(event: HDWPEvent) -> None:
        obs_events.append(event)

    async def model_handler(event: HDWPEvent) -> None:
        model_events.append(event)

    bus.on(OBSERVATION_RAW, obs_handler, mode="stream")
    bus.on(MODEL_UPDATED, model_handler, mode="stream")

    await bus.emit(OBSERVATION_RAW, "obs_only", source="test")

    assert len(obs_events) == 1
    assert len(model_events) == 0

    await bus.emit(MODEL_UPDATED, "model_only", source="test")

    assert len(obs_events) == 1
    assert len(model_events) == 1


@pytest.mark.asyncio
async def test_stream_events_appear_in_history(bus: AsyncEventBus) -> None:
    async def noop(event: HDWPEvent) -> None:
        pass

    bus.on(OBSERVATION_RAW, noop, mode="stream")

    await bus.emit(OBSERVATION_RAW, "hist_1", source="test")
    await bus.emit(OBSERVATION_RAW, "hist_2", source="test")

    history = bus.history
    assert len(history) == 2
    assert history[0].payload == "hist_1"
    assert history[1].payload == "hist_2"


@pytest.mark.asyncio
async def test_stream_fires_before_batch_on_same_emit(bus: AsyncEventBus) -> None:
    order: list[str] = []

    async def stream_handler(event: HDWPEvent) -> None:
        order.append("stream")

    async def batch_handler(event: HDWPEvent) -> None:
        order.append("batch")

    bus.on(OBSERVATION_RAW, stream_handler, mode="stream")
    bus.on(OBSERVATION_RAW, batch_handler)

    await bus.emit(OBSERVATION_RAW, "ordering", source="test")
    assert order == ["stream"]

    await bus.drain()
    assert order == ["stream", "batch"]
