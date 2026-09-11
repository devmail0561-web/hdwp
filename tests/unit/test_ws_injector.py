# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest


class _FakeWS:
    def __init__(self, response: str | bytes | None = None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.sent: list[str | bytes] = []

    async def recv(self):
        if self._error:
            raise self._error
        if self._response is None:
            raise asyncio.TimeoutError
        return self._response

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
async def test_execute_returns_response():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    fake_ws = _FakeWS(response='{"result":"reflected"}')
    injector = WebSocketInjector(timeout=1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", _make_connect(fake_ws)):
        result = await injector.execute("ws://target/ws", payload="<script>alert(1)</script>")

    assert result.status_code == 101
    # normalize_response parses JSON bodies into dicts
    assert result.body == {"result": "reflected"}
    assert result.timing_ms > 0
    assert fake_ws.sent == ["<script>alert(1)</script>"]


@pytest.mark.asyncio
async def test_execute_auth_headers():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    fake_ws = _FakeWS(response="ok")
    connect_mock = MagicMock(return_value=fake_ws)
    injector = WebSocketInjector(timeout=1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", connect_mock):
        await injector.execute(
            "wss://target/ws",
            payload="test",
            auth_headers={"Authorization": "Bearer tok123"},
        )

    kwargs = connect_mock.call_args.kwargs
    assert kwargs["additional_headers"] == {"Authorization": "Bearer tok123"}


@pytest.mark.asyncio
async def test_execute_connection_refused():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    class _FailingWS:
        async def __aenter__(self):
            raise OSError("Connection refused")

        async def __aexit__(self, *args):
            pass

    injector = WebSocketInjector(timeout=0.1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", lambda *a, **kw: _FailingWS()):
        result = await injector.execute("ws://invalid/ws", payload="test")

    assert result.status_code == 0
    assert result.timing_ms > 0


@pytest.mark.asyncio
async def test_execute_timeout():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    fake_ws = _FakeWS(response=None)  # recv() raises TimeoutError
    injector = WebSocketInjector(timeout=0.1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", _make_connect(fake_ws)):
        result = await injector.execute("ws://target/ws", payload="test")

    assert result.status_code == 0


@pytest.mark.asyncio
async def test_send_raw_delegates_to_execute():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    fake_ws = _FakeWS(response="pong")
    injector = WebSocketInjector(timeout=1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", _make_connect(fake_ws)):
        result = await injector.send_raw("ws://target/ws", payload="ping")

    assert result.status_code == 101
    assert fake_ws.sent == ["ping"]


@pytest.mark.asyncio
async def test_send_raw_empty_payload():
    from hdwp.core.experiment.ws_injector import WebSocketInjector

    fake_ws = _FakeWS(response="ok")
    injector = WebSocketInjector(timeout=1)

    with patch("hdwp.core.experiment.ws_injector.websockets.connect", _make_connect(fake_ws)):
        result = await injector.send_raw("ws://target/ws")

    assert fake_ws.sent == [""]
    assert result.status_code == 101
