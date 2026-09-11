# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

grpc = pytest.importorskip("grpc")

from hdwp.core.model.schemas import NormalizedRequest


@pytest.mark.asyncio
async def test_execute_success():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()
    mock_unary = AsyncMock(return_value={"user_id": "1", "name": "admin"})
    mock_channel.unary_unary.return_value = mock_unary

    injector = GrpcInjector(timeout=5)

    with patch("hdwp.core.experiment.grpc_injector.grpc.aio.insecure_channel", return_value=mock_channel):
        result = await injector.execute(
            target="localhost:50051",
            service="myapp.UserService",
            method="GetUser",
            payload={"user_id": "1' OR 1=1--"},
        )

    assert result.status_code == 200
    assert result.timing_ms > 0
    mock_channel.unary_unary.assert_called_once()


@pytest.mark.asyncio
async def test_execute_tls():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()
    mock_channel.unary_unary.return_value = AsyncMock(return_value={})

    injector = GrpcInjector(timeout=5)

    with (
        patch("hdwp.core.experiment.grpc_injector.grpc.aio.secure_channel", return_value=mock_channel) as mock_secure,
        patch("hdwp.core.experiment.grpc_injector.grpc.ssl_channel_credentials") as mock_creds,
    ):
        await injector.execute(
            target="target:443",
            service="svc",
            method="Method",
            payload={},
            tls=True,
        )

    mock_secure.assert_called_once()
    mock_creds.assert_called_once()


@pytest.mark.asyncio
async def test_execute_permission_denied_maps_to_403():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()

    rpc_error = grpc.RpcError()
    rpc_error.code = lambda: grpc.StatusCode.PERMISSION_DENIED
    mock_channel.unary_unary.return_value = AsyncMock(side_effect=rpc_error)

    injector = GrpcInjector(timeout=5)

    with patch("hdwp.core.experiment.grpc_injector.grpc.aio.insecure_channel", return_value=mock_channel):
        result = await injector.execute(
            target="localhost:50051",
            service="svc",
            method="Admin",
            payload={"action": "delete_all"},
        )

    assert result.status_code == 403


@pytest.mark.asyncio
async def test_execute_not_found_maps_to_404():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()

    rpc_error = grpc.RpcError()
    rpc_error.code = lambda: grpc.StatusCode.NOT_FOUND
    mock_channel.unary_unary.return_value = AsyncMock(side_effect=rpc_error)

    injector = GrpcInjector(timeout=5)

    with patch("hdwp.core.experiment.grpc_injector.grpc.aio.insecure_channel", return_value=mock_channel):
        result = await injector.execute(
            target="localhost:50051",
            service="svc",
            method="Missing",
            payload={},
        )

    assert result.status_code == 404


@pytest.mark.asyncio
async def test_send_raw_parses_url():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()
    mock_channel.unary_unary.return_value = AsyncMock(return_value={})

    injector = GrpcInjector(timeout=5)

    req = NormalizedRequest(
        method="POST",
        url="grpc://localhost:50051/myapp.UserService/GetUser",
        body={"user_id": "1"},
    )

    with patch("hdwp.core.experiment.grpc_injector.grpc.aio.insecure_channel", return_value=mock_channel):
        result = await injector.send_raw(req)

    assert result.status_code == 200
    call_args = mock_channel.unary_unary.call_args
    assert call_args.args[0] == "/myapp.UserService/GetUser"


@pytest.mark.asyncio
async def test_execute_auth_metadata():
    from hdwp.core.experiment.grpc_injector import GrpcInjector

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()
    mock_call = AsyncMock(return_value={})
    mock_channel.unary_unary.return_value = mock_call

    injector = GrpcInjector(timeout=5)

    with patch("hdwp.core.experiment.grpc_injector.grpc.aio.insecure_channel", return_value=mock_channel):
        await injector.execute(
            target="localhost:50051",
            service="svc",
            method="Method",
            payload={},
            auth_headers={"authorization": "Bearer tok"},
        )

    call_kwargs = mock_call.call_args.kwargs
    assert ("authorization", "Bearer tok") in call_kwargs["metadata"]
