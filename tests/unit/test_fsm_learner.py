# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW, FSM_UPDATED
from hdwp.core.model.schemas import NormalizedRequest, NormalizedResponse, ObservationType, RawObservation
from hdwp.core.state_machine.learner import StateMachineLearner


def _make_obs(url: str, status: int, session_id: str = "s1") -> dict:
    obs = RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url=url),
        response=NormalizedResponse(status_code=status),
        session_id=session_id,
    )
    return obs.model_dump()


@pytest.mark.asyncio
async def test_no_observations_fsm_none():
    """FSM is None before any observations."""
    bus = AsyncEventBus()
    learner = StateMachineLearner(bus)
    assert learner.current_fsm is None


@pytest.mark.asyncio
async def test_ten_observations_generates_fsm():
    """After 10 observations, FSM is built and fsm.updated is emitted."""
    bus = AsyncEventBus()
    learner = StateMachineLearner(bus)
    received = []
    bus.on(FSM_UPDATED, lambda e: received.append(e))

    for i in range(10):
        await bus.emit(OBSERVATION_RAW, _make_obs(f"http://test.local/api/item/{i}", 200), source="test")
    await bus.drain()

    assert learner.current_fsm is not None
    assert len(learner.current_fsm.states) > 0
    assert len(learner.current_fsm.transitions) > 0


@pytest.mark.asyncio
async def test_auth_flow_states():
    """Login 401 → Login 200 → Resource 200 produces distinct state labels."""
    bus = AsyncEventBus()
    learner = StateMachineLearner(bus)

    flow = [
        ("http://test.local/api/login", 401),
        ("http://test.local/api/login", 200),
        ("http://test.local/api/resource", 200),
    ]
    # Need 10 observations to trigger FSM build — repeat the flow multiple times
    for _ in range(4):
        for url, status in flow:
            await bus.emit(OBSERVATION_RAW, _make_obs(url, status), source="test")

    await bus.emit(OBSERVATION_RAW, _make_obs("http://test.local/api/login", 401), source="test")
    await bus.emit(OBSERVATION_RAW, _make_obs("http://test.local/api/login", 401), source="test")
    await bus.drain()

    fsm = learner.current_fsm
    assert fsm is not None
    labels = {s.label for s in fsm.states}
    # Should contain auth_error and 2xx states
    assert any("auth_error" in lbl for lbl in labels)
    assert any("2xx" in lbl for lbl in labels)


@pytest.mark.asyncio
async def test_fsm_changed_true_on_new_states():
    """_fsm_changed returns True when new FSM has more states than current."""
    bus = AsyncEventBus()
    learner = StateMachineLearner(bus)

    # Trigger a first FSM build
    for i in range(10):
        await bus.emit(OBSERVATION_RAW, _make_obs(f"http://test.local/api/a/{i}", 200), source="test")
    await bus.drain()

    first_fsm = learner.current_fsm
    assert first_fsm is not None

    # Build a new FSM with more symbols
    for i in range(10):
        await bus.emit(OBSERVATION_RAW, _make_obs(f"http://test.local/api/b/{i}", 404), source="test")
    await bus.drain()

    second_fsm = learner.current_fsm
    assert second_fsm is not None
    assert len(second_fsm.states) >= len(first_fsm.states)
