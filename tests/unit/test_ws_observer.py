# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.model.schemas import ObservationType


@pytest.fixture()
def bus():
    b = AsyncMock()
    b.emit = AsyncMock()
    return b


class _FakeWS:
    """Simulates a websockets connection context manager."""

    def __init__(self, messages: list[str | bytes], subprotocol: str | None = None):
        self._messages = list(messages)
        self._idx = 0
        self.subprotocol = subprotocol
        self.sent: list[str | bytes] = []

    async def recv(self):
        if self._idx < len(self._messages):
            msg = self._messages[self._idx]
            self._idx += 1
            return msg
        raise asyncio.TimeoutError

    async def send(self, data):
        self.sent.append(data)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def _make_connect(ws_instance):
    def connect(*args, **kwargs):
        return ws_instance
    return connect


@pytest.mark.asyncio
async def test_observe_emits_ws_observations(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS(['{"event":"hello"}', '{"event":"update"}'])
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=1, max_messages=5)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    emitted = bus.emit.call_args_list
    # 2 messages + 1 probe (probe times out → no emission for probe)
    assert len(emitted) >= 2
    first_payload = emitted[0].args[1]
    assert first_payload["type"] == ObservationType.WS
    assert first_payload["artefact"]["ws_url"] == "ws://target/ws"
    assert first_payload["artefact"]["format"] == "json"
    assert first_payload["artefact"]["is_binary"] is False


@pytest.mark.asyncio
async def test_observe_auth_headers_propagated(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS([])
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=0.1)

    connect_mock = MagicMock(return_value=fake_ws)
    with patch("hdwp.core.observation.ws_observer.websockets.connect", connect_mock):
        await observer.observe(
            ["wss://target/ws"],
            auth_headers={"Authorization": "Bearer tok"},
        )

    connect_mock.assert_called_once()
    kwargs = connect_mock.call_args.kwargs
    assert kwargs["additional_headers"] == {"Authorization": "Bearer tok"}


@pytest.mark.asyncio
async def test_observe_binary_message(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS([b"\x80\x01\x02\x03"])
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=1, max_messages=5)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    emitted = bus.emit.call_args_list
    assert len(emitted) >= 1
    payload = emitted[0].args[1]
    assert payload["artefact"]["is_binary"] is True
    assert payload["artefact"]["format"] == "msgpack"


@pytest.mark.asyncio
async def test_observe_text_format(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS(["hello world"])
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=1, max_messages=5)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    payload = bus.emit.call_args_list[0].args[1]
    assert payload["artefact"]["format"] == "text"


@pytest.mark.asyncio
async def test_observe_connection_failure_no_crash(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=0.1)

    class _FailingWS:
        async def __aenter__(self):
            raise OSError("Connection refused")

        async def __aexit__(self, *args):
            pass

    with patch("hdwp.core.observation.ws_observer.websockets.connect", lambda *a, **kw: _FailingWS()):
        await observer.observe(["ws://invalid:9999/ws"])

    bus.emit.assert_not_called()


@pytest.mark.asyncio
async def test_observe_timeout_graceful(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS([])  # No messages → immediate timeout
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=0.1, max_messages=5)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    # No message received → no observation emitted (only probe attempt)
    assert bus.emit.call_count == 0


@pytest.mark.asyncio
async def test_observe_probe_emitted(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    # First message is observed, then probe gets a response
    fake_ws = _FakeWS(['{"event":"data"}', '{"type":"pong"}'])
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=1, max_messages=1)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    # 1 observed message + 1 probe response
    assert bus.emit.call_count == 2
    probe_payload = bus.emit.call_args_list[1].args[1]
    assert probe_payload["artefact"].get("probe") is True
    assert "ws:probe" in probe_payload["tags"]


@pytest.mark.asyncio
async def test_observe_subprotocol_recorded(bus):
    from hdwp.core.observation.ws_observer import WebSocketObserver

    fake_ws = _FakeWS(['{"msg":"hi"}'], subprotocol="graphql-ws")
    observer = WebSocketObserver(bus=bus, session_id="s1", timeout=1, max_messages=5)

    with patch("hdwp.core.observation.ws_observer.websockets.connect", _make_connect(fake_ws)):
        await observer.observe(["ws://target/ws"])

    payload = bus.emit.call_args_list[0].args[1]
    assert payload["artefact"]["subprotocol"] == "graphql-ws"
