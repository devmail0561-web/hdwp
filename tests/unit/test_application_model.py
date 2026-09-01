# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import MODEL_UPDATED, OBSERVATION_RAW, HDWPEvent
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import (
    NormalizedRequest,
    NormalizedResponse,
    ObservationType,
    RawObservation,
)


def _make_obs(
    url: str = "http://test.local/api/users/123",
    method: str = "GET",
    resp_body: dict | None = None,
    headers: dict[str, str] | None = None,
    session_id: str = "sess-anon",
) -> dict:
    return RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(
            method=method,
            url=url,
            headers=headers or {},
        ),
        response=NormalizedResponse(
            status_code=200,
            body=resp_body if resp_body is not None else {"id": 123, "name": "test"},
            content_type="application/json",
        ),
        session_id=session_id,
    ).model_dump()


@pytest.fixture
def bus() -> AsyncEventBus:
    return AsyncEventBus(max_history=100)


@pytest.mark.asyncio
async def test_model_updates_on_observation(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    await bus.emit(OBSERVATION_RAW, _make_obs(), source="test")
    await bus.drain()

    snap = model.snapshot()
    assert len(snap.endpoints) == 1
    assert snap.endpoints[0].path == "/api/users/{id_0}"
    assert "GET" in snap.endpoints[0].methods

    path_params = [p for p in snap.parameters if p.location == "path"]
    assert len(path_params) >= 1
    assert path_params[0].type_inferred == "integer"


@pytest.mark.asyncio
async def test_multiple_observations_deduplicate(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)

    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(url="http://test.local/api/users/1"),
        source="test",
    )
    await bus.drain()
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(url="http://test.local/api/users/2"),
        source="test",
    )
    await bus.drain()
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(url="http://test.local/api/users", method="POST", resp_body={"id": 3, "name": "new"}),
        source="test",
    )
    await bus.drain()

    snap = model.snapshot()
    get_eps = [e for e in snap.endpoints if "GET" in e.methods]
    post_eps = [e for e in snap.endpoints if "POST" in e.methods]
    assert len(get_eps) == 1
    assert len(post_eps) == 1
    assert get_eps[0].path == "/api/users/{id_0}"
    assert post_eps[0].path == "/api/users"


@pytest.mark.asyncio
async def test_data_objects_from_json_responses(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(resp_body={"id": 1, "name": "test", "email": "t@x.com"}),
        source="test",
    )
    await bus.drain()

    snap = model.snapshot()
    assert len(snap.objects) == 1
    obj = snap.objects[0]
    assert "id" in obj.schema_def
    assert "name" in obj.schema_def
    assert "email" in obj.schema_def


@pytest.mark.asyncio
async def test_role_tracking(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)

    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(headers={"authorization": "Bearer tok123"}, session_id="sess-auth"),
        source="test",
    )
    await bus.drain()
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(session_id="sess-anon"),
        source="test",
    )
    await bus.drain()

    snap = model.snapshot()
    role_names = {r.name for r in snap.roles}
    assert "anonymous" in role_names
    assert any(r.startswith("authenticated_") for r in role_names)


@pytest.mark.asyncio
async def test_model_updated_event_published(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(MODEL_UPDATED, handler)

    await bus.emit(OBSERVATION_RAW, _make_obs(), source="test")
    await bus.drain()

    assert len(received) >= 1
    assert received[0].type == MODEL_UPDATED


@pytest.mark.asyncio
async def test_affects_object_detection(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(
            url="http://test.local/api/users/42",
            resp_body={"id": 42, "name": "test"},
        ),
        source="test",
    )
    await bus.drain()

    snap = model.snapshot()
    path_params = [p for p in snap.parameters if p.location == "path"]
    assert len(path_params) >= 1
    assert path_params[0].affects_object is not None
    assert path_params[0].affects_object.startswith("OBJ-")


@pytest.mark.asyncio
async def test_uuid_path_parameter(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(
            url="http://test.local/api/items/550e8400-e29b-41d4-a716-446655440000",
            resp_body={"uuid": "550e8400-e29b-41d4-a716-446655440000", "label": "x"},
        ),
        source="test",
    )
    await bus.drain()

    snap = model.snapshot()
    assert snap.endpoints[0].path == "/api/items/{uuid_0}"
    uuid_params = [p for p in snap.parameters if p.type_inferred == "uuid"]
    assert len(uuid_params) >= 1


@pytest.mark.asyncio
async def test_query_params_tracked(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    obs = _make_obs(url="http://test.local/api/search")
    obs["request"]["query_params"] = {"q": "test", "page": "2"}
    await bus.emit(OBSERVATION_RAW, obs, source="test")
    await bus.drain()

    snap = model.snapshot()
    query_params = [p for p in snap.parameters if p.location == "query"]
    names = {p.name for p in query_params}
    assert "q" in names
    assert "page" in names


@pytest.mark.asyncio
async def test_body_params_tracked(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    await bus.emit(
        OBSERVATION_RAW,
        _make_obs(
            url="http://test.local/api/users",
            method="POST",
            resp_body={"id": 1, "name": "new"},
        ),
        source="test",
    )
    # The request body needs to be a dict for body params
    obs = _make_obs(url="http://test.local/api/login", method="POST", resp_body={"token": "abc"})
    obs["request"]["body"] = {"username": "admin", "password": "secret"}
    await bus.emit(OBSERVATION_RAW, obs, source="test")
    await bus.drain()

    snap = model.snapshot()
    body_params = [p for p in snap.parameters if p.location == "body"]
    names = {p.name for p in body_params}
    assert "username" in names
    assert "password" in names


@pytest.mark.asyncio
async def test_observation_without_request_ignored(bus: AsyncEventBus) -> None:
    model = ApplicationModel(bus)
    obs = RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="passive",
        type=ObservationType.HEADER,
        request=None,
        response=None,
        session_id="sess",
    ).model_dump()
    await bus.emit(OBSERVATION_RAW, obs, source="test")
    await bus.drain()

    snap = model.snapshot()
    assert len(snap.endpoints) == 0


@pytest.mark.asyncio
async def test_fsm_stored_from_event(bus: AsyncEventBus) -> None:
    """FSM reçue via fsm.updated doit être stockée dans le snapshot."""
    from hdwp.core.bus.events import FSM_UPDATED
    from hdwp.core.model.schemas import ApplicationFSM, FSMState, generate_id

    app_model = ApplicationModel(bus)
    fsm = ApplicationFSM(
        id=generate_id("FSM"),
        states=[FSMState(label="initial"), FSMState(label="authenticated")],
        initial_state="FSM-S-init",
        confidence=0.7,
    )

    await bus.emit(FSM_UPDATED, fsm.model_dump(), source="test")
    await bus.drain()

    snapshot = app_model.snapshot()
    assert snapshot.fsm is not None
    assert len(snapshot.fsm.states) == 2
