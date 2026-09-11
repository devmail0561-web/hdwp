# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from hdwp.core.model.schemas import NormalizedRequest


@pytest.mark.asyncio
async def test_dispatch_http_delegates_to_send_http():
    from hdwp.core.experiment.protocol_dispatch import dispatch_send

    client = AsyncMock()
    fake_response = AsyncMock()
    client.request.return_value = fake_response

    req = NormalizedRequest(method="GET", url="https://target.com/api/users")
    result = await dispatch_send(client, req)

    client.request.assert_called_once()
    assert result is fake_response


@pytest.mark.asyncio
async def test_dispatch_ws_delegates_to_ws_injector():
    from hdwp.core.experiment.protocol_dispatch import dispatch_send

    mock_resp = AsyncMock()
    with patch("hdwp.core.experiment.ws_injector.WebSocketInjector.send_raw", return_value=mock_resp) as mock_send:
        req = NormalizedRequest(method="GET", url="ws://target.com/ws")
        result = await dispatch_send(AsyncMock(), req)

    mock_send.assert_called_once_with("ws://target.com/ws", payload=None, auth_headers=None)
    assert result is mock_resp


@pytest.mark.asyncio
async def test_dispatch_wss_delegates_to_ws_injector():
    from hdwp.core.experiment.protocol_dispatch import dispatch_send

    mock_resp = AsyncMock()
    with patch("hdwp.core.experiment.ws_injector.WebSocketInjector.send_raw", return_value=mock_resp):
        req = NormalizedRequest(method="GET", url="wss://target.com/ws")
        result = await dispatch_send(AsyncMock(), req)

    assert result is mock_resp


@pytest.mark.asyncio
async def test_dispatch_grpc_delegates_to_grpc_injector():
    from hdwp.core.experiment.protocol_dispatch import dispatch_send

    mock_resp = AsyncMock()
    with patch("hdwp.core.experiment.grpc_injector.GrpcInjector.send_raw", return_value=mock_resp, create=True) as mock_send:
        req = NormalizedRequest(method="GET", url="grpc://target.com:50051/svc/Method")
        result = await dispatch_send(AsyncMock(), req)

    assert result is mock_resp


@pytest.mark.asyncio
async def test_send_http_json_body():
    from hdwp.core.experiment.protocol_dispatch import send_http

    client = AsyncMock()
    fake_response = AsyncMock()
    client.request.return_value = fake_response

    req = NormalizedRequest(
        method="POST",
        url="https://target.com/api/login",
        headers={"Content-Type": "application/json"},
        body={"username": "admin", "password": "test"},
    )
    result = await send_http(client, req)

    client.request.assert_called_once()
    kwargs = client.request.call_args.kwargs
    assert kwargs["json"] == {"username": "admin", "password": "test"}


@pytest.mark.asyncio
async def test_send_http_string_body():
    from hdwp.core.experiment.protocol_dispatch import send_http

    client = AsyncMock()
    client.request.return_value = AsyncMock()

    req = NormalizedRequest(
        method="POST",
        url="https://target.com/api",
        body="raw body content",
    )
    await send_http(client, req)

    kwargs = client.request.call_args.kwargs
    assert kwargs["content"] == b"raw body content"


@pytest.mark.asyncio
async def test_send_http_raw_body_override():
    from hdwp.core.experiment.protocol_dispatch import send_http

    client = AsyncMock()
    client.request.return_value = AsyncMock()

    req = NormalizedRequest(
        method="POST",
        url="https://target.com/api",
        raw_body_override=b"smuggled\r\n\r\nGET /admin",
    )
    await send_http(client, req)

    kwargs = client.request.call_args.kwargs
    assert kwargs["content"] == b"smuggled\r\n\r\nGET /admin"


@pytest.mark.asyncio
async def test_send_http_strips_redacted_headers():
    from hdwp.core.experiment.protocol_dispatch import send_http

    client = AsyncMock()
    client.request.return_value = AsyncMock()

    req = NormalizedRequest(
        method="GET",
        url="https://target.com/api",
        headers={"Authorization": "[REDACTED]", "Accept": "application/json"},
    )
    await send_http(client, req)

    kwargs = client.request.call_args.kwargs
    assert "Authorization" not in kwargs["headers"]
    assert kwargs["headers"]["Accept"] == "application/json"
