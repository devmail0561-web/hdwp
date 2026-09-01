# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import MODEL_UPDATED, OBSERVATION_RAW, HDWPEvent


@pytest.fixture
def bus() -> AsyncEventBus:
    return AsyncEventBus(max_history=50)


@pytest.mark.asyncio
async def test_emit_and_receive(bus: AsyncEventBus) -> None:
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    await bus.emit(OBSERVATION_RAW, {"data": "test"}, source="test")
    await bus.drain()

    assert len(received) == 1
    assert received[0].type == OBSERVATION_RAW
    assert received[0].payload == {"data": "test"}
    assert received[0].source == "test"


@pytest.mark.asyncio
async def test_multiple_subscribers(bus: AsyncEventBus) -> None:
    results_a: list[HDWPEvent] = []
    results_b: list[HDWPEvent] = []

    async def handler_a(event: HDWPEvent) -> None:
        results_a.append(event)

    async def handler_b(event: HDWPEvent) -> None:
        results_b.append(event)

    bus.on(OBSERVATION_RAW, handler_a)
    bus.on(OBSERVATION_RAW, handler_b)
    await bus.emit(OBSERVATION_RAW, "payload", source="test")
    await bus.drain()

    assert len(results_a) == 1
    assert len(results_b) == 1


@pytest.mark.asyncio
async def test_different_event_types_isolated(bus: AsyncEventBus) -> None:
    obs_events: list[HDWPEvent] = []
    model_events: list[HDWPEvent] = []

    async def obs_handler(event: HDWPEvent) -> None:
        obs_events.append(event)

    async def model_handler(event: HDWPEvent) -> None:
        model_events.append(event)

    bus.on(OBSERVATION_RAW, obs_handler)
    bus.on(MODEL_UPDATED, model_handler)

    await bus.emit(OBSERVATION_RAW, "obs", source="test")
    await bus.emit(MODEL_UPDATED, "model", source="test")
    await bus.drain()

    assert len(obs_events) == 1
    assert len(model_events) == 1
    assert obs_events[0].payload == "obs"
    assert model_events[0].payload == "model"


@pytest.mark.asyncio
async def test_wait_for(bus: AsyncEventBus) -> None:
    async def delayed_emit() -> None:
        await asyncio.sleep(0.05)
        await bus.emit(OBSERVATION_RAW, "waited", source="test")

    asyncio.create_task(delayed_emit())
    event = await bus.wait_for(OBSERVATION_RAW, timeout=2.0)

    assert event.type == OBSERVATION_RAW
    assert event.payload == "waited"


@pytest.mark.asyncio
async def test_wait_for_timeout(bus: AsyncEventBus) -> None:
    with pytest.raises(asyncio.TimeoutError):
        await bus.wait_for(OBSERVATION_RAW, timeout=0.05)


@pytest.mark.asyncio
async def test_drain_completes_when_handlers_finish(bus: AsyncEventBus) -> None:
    completed = False

    async def slow_handler(event: HDWPEvent) -> None:
        nonlocal completed
        await asyncio.sleep(0.1)
        completed = True

    bus.on(OBSERVATION_RAW, slow_handler)
    await bus.emit(OBSERVATION_RAW, "slow", source="test")
    await bus.drain()

    assert completed is True


@pytest.mark.asyncio
async def test_history_stores_events(bus: AsyncEventBus) -> None:
    for i in range(5):
        await bus.emit(OBSERVATION_RAW, f"event-{i}", source="test")

    history = bus.history
    assert len(history) == 5
    assert history[0].payload == "event-0"
    assert history[4].payload == "event-4"


@pytest.mark.asyncio
async def test_history_truncated_at_max() -> None:
    bus = AsyncEventBus(max_history=3)
    for i in range(10):
        await bus.emit(OBSERVATION_RAW, f"event-{i}", source="test")

    history = bus.history
    assert len(history) == 3
    assert history[0].payload == "event-7"
    assert history[2].payload == "event-9"
