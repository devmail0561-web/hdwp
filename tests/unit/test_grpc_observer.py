# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

grpc = pytest.importorskip("grpc")

from hdwp.core.model.schemas import ObservationType


@pytest.fixture()
def bus():
    b = AsyncMock()
    b.emit = AsyncMock()
    return b


@pytest.mark.asyncio
async def test_observe_via_reflection(bus):
    from hdwp.core.observation.grpc_observer import GrpcObserver

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_services.return_value = ["myapp.UserService"]

    observer = GrpcObserver(bus=bus, session_id="s1")

    with (
        patch("hdwp.core.observation.grpc_observer.grpc.aio.insecure_channel", return_value=mock_channel),
        patch("hdwp.core.observation.grpc_observer.ProtoReflectionDescriptorDatabase", return_value=mock_db),
    ):
        await observer.observe("localhost:50051")

    assert bus.emit.call_count >= 1
    payload = bus.emit.call_args_list[0].args[1]
    assert payload["type"] == ObservationType.GRPC
    assert payload["artefact"]["service"] == "myapp.UserService"
    assert payload["artefact"]["target"] == "localhost:50051"


@pytest.mark.asyncio
async def test_observe_tls_uses_secure_channel(bus):
    from hdwp.core.observation.grpc_observer import GrpcObserver

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_services.return_value = []

    observer = GrpcObserver(bus=bus, session_id="s1")

    with (
        patch("hdwp.core.observation.grpc_observer.grpc.aio.secure_channel", return_value=mock_channel) as mock_secure,
        patch("hdwp.core.observation.grpc_observer.grpc.ssl_channel_credentials") as mock_creds,
        patch("hdwp.core.observation.grpc_observer.ProtoReflectionDescriptorDatabase", return_value=mock_db),
    ):
        await observer.observe("target:443", tls=True)

    mock_secure.assert_called_once()
    mock_creds.assert_called_once()


@pytest.mark.asyncio
async def test_observe_no_reflection_fallback(bus):
    from hdwp.core.observation.grpc_observer import GrpcObserver

    mock_channel = AsyncMock()
    mock_channel.close = AsyncMock()

    observer = GrpcObserver(bus=bus, session_id="s1")

    def raise_rpc_error(*args, **kwargs):
        raise grpc.RpcError()

    with (
        patch("hdwp.core.observation.grpc_observer.grpc.aio.insecure_channel", return_value=mock_channel),
        patch("hdwp.core.observation.grpc_observer.ProtoReflectionDescriptorDatabase", side_effect=raise_rpc_error),
    ):
        await observer.observe("localhost:50051")

    assert bus.emit.call_count == 1
    payload = bus.emit.call_args_list[0].args[1]
    assert payload["artefact"]["service"] == "unknown"
    assert "grpc:no_reflection" in payload["tags"]


@pytest.mark.asyncio
async def test_observe_from_proto_file(bus):
    from hdwp.core.observation.grpc_observer import GrpcObserver

    proto_content = """
syntax = "proto3";

service UserService {
    rpc GetUser (GetUserRequest) returns (UserResponse);
    rpc ListUsers (ListUsersRequest) returns (ListUsersResponse);
}

service AdminService {
    rpc DeleteUser (DeleteUserRequest) returns (Empty);
}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".proto", delete=False) as f:
        f.write(proto_content)
        proto_path = f.name

    try:
        observer = GrpcObserver(bus=bus, session_id="s1")
        await observer.observe("localhost:50051", proto_files=[proto_path])

        assert bus.emit.call_count == 2
        payloads = [call.args[1] for call in bus.emit.call_args_list]

        services = {p["artefact"]["service"] for p in payloads}
        assert services == {"UserService", "AdminService"}

        user_svc = next(p for p in payloads if p["artefact"]["service"] == "UserService")
        assert len(user_svc["artefact"]["methods"]) == 2
        method_names = {m["name"] for m in user_svc["artefact"]["methods"]}
        assert method_names == {"GetUser", "ListUsers"}
        assert "grpc:from_proto" in user_svc["tags"]
    finally:
        os.unlink(proto_path)
