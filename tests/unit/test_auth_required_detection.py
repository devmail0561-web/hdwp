# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import NormalizedRequest, NormalizedResponse, ObservationType, RawObservation


def _obs(url: str, role: str, status: int) -> RawObservation:
    return RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url=url),
        response=NormalizedResponse(status_code=status, body=None),
        session_id="test",
        tags=[f"role:{role}"],
    )


@pytest.mark.asyncio
async def test_auth_required_detected_after_anonymous_401_and_user_200() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    await bus.emit("observation.raw", _obs("http://t/api/admin", "anonymous", 401).model_dump(), source="test")
    await bus.emit("observation.raw", _obs("http://t/api/admin", "user_a", 200).model_dump(), source="test")
    await bus.drain()

    snap = model.snapshot()
    ep = next((e for e in snap.endpoints if e.path == "/api/admin"), None)
    assert ep is not None
    assert ep.auth_required is True
    assert "user_a" in ep.roles_observed


@pytest.mark.asyncio
async def test_auth_required_not_set_when_anonymous_200() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    await bus.emit("observation.raw", _obs("http://t/api/public", "anonymous", 200).model_dump(), source="test")
    await bus.drain()

    snap = model.snapshot()
    ep = next((e for e in snap.endpoints if e.path == "/api/public"), None)
    assert ep is not None
    assert ep.auth_required is False


@pytest.mark.asyncio
async def test_auth_required_with_two_authenticated_roles() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    await bus.emit("observation.raw", _obs("http://t/api/secret", "anonymous", 403).model_dump(), source="test")
    await bus.emit("observation.raw", _obs("http://t/api/secret", "user_a", 200).model_dump(), source="test")
    await bus.emit("observation.raw", _obs("http://t/api/secret", "user_b", 200).model_dump(), source="test")
    await bus.drain()

    snap = model.snapshot()
    ep = next((e for e in snap.endpoints if e.path == "/api/secret"), None)
    assert ep is not None
    assert ep.auth_required is True
    assert "user_a" in ep.roles_observed
    assert "user_b" in ep.roles_observed


@pytest.mark.asyncio
async def test_auth_required_not_set_when_only_anonymous_observed() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    # Only anonymous with 401 — no auth success → not enough info
    await bus.emit("observation.raw", _obs("http://t/api/private", "anonymous", 401).model_dump(), source="test")
    await bus.drain()

    snap = model.snapshot()
    ep = next((e for e in snap.endpoints if e.path == "/api/private"), None)
    assert ep is not None
    assert ep.auth_required is False  # need confirmed auth success too


@pytest.mark.asyncio
async def test_auth_required_order_independent() -> None:
    """Auth success observed before anonymous 401 — should still work."""
    bus = AsyncEventBus()
    model = ApplicationModel(bus)

    await bus.emit("observation.raw", _obs("http://t/api/order", "admin", 200).model_dump(), source="test")
    await bus.emit("observation.raw", _obs("http://t/api/order", "anonymous", 401).model_dump(), source="test")
    await bus.drain()

    snap = model.snapshot()
    ep = next((e for e in snap.endpoints if e.path == "/api/order"), None)
    assert ep is not None
    assert ep.auth_required is True
    assert "admin" in ep.roles_observed
