import pytest
from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.server.event_bridge import EventBridge
from hdwp.server.ws_manager import WebSocketManager


@pytest.mark.asyncio
async def test_event_bridge_attach_no_exception():
    bus = AsyncEventBus()
    ws_manager = WebSocketManager()
    bridge = EventBridge(bus, ws_manager)
    bridge.attach()
    await bus.emit("finding.confirmed", {"id": "FIND-test"}, source="test")
    await bus.drain()


@pytest.mark.asyncio
async def test_event_bridge_factory_captures_correct_event_type():
    received: list[str] = []

    class MockWS:
        async def send_json(self, data: dict) -> None:
            received.append(data["type"])

    bus = AsyncEventBus()
    ws_manager = WebSocketManager()
    ws_manager._connections.add(MockWS())  # type: ignore[arg-type]

    bridge = EventBridge(bus, ws_manager)
    bridge.attach()

    await bus.emit("observation.raw", {"url": "/api/test"}, source="test")
    await bus.drain()

    assert "observation.raw" in received
    assert all(e == "observation.raw" for e in received)


@pytest.mark.asyncio
async def test_event_bridge_multiple_event_types():
    received: dict[str, int] = {}

    class MockWS:
        async def send_json(self, data: dict) -> None:
            received[data["type"]] = received.get(data["type"], 0) + 1

    bus = AsyncEventBus()
    ws_manager = WebSocketManager()
    ws_manager._connections.add(MockWS())  # type: ignore[arg-type]

    bridge = EventBridge(bus, ws_manager)
    bridge.attach()

    await bus.emit("observation.raw", {}, source="test")
    await bus.emit("finding.confirmed", {"id": "F1"}, source="test")
    await bus.drain()

    assert received.get("observation.raw") == 1
    assert received.get("finding.confirmed") == 1
