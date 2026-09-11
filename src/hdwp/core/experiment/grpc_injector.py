# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import time
from typing import Any

import structlog

from hdwp.core.model.schemas import NormalizedRequest, NormalizedResponse
from hdwp.core.observation.normalizer import normalize_response

log = structlog.get_logger()

try:
    import grpc
    import grpc.aio

    _GRPC_TO_HTTP: dict[Any, int] = {
        grpc.StatusCode.OK: 200,
        grpc.StatusCode.INVALID_ARGUMENT: 400,
        grpc.StatusCode.UNAUTHENTICATED: 401,
        grpc.StatusCode.PERMISSION_DENIED: 403,
        grpc.StatusCode.NOT_FOUND: 404,
        grpc.StatusCode.INTERNAL: 500,
        grpc.StatusCode.UNAVAILABLE: 503,
    }
    _HAS_GRPC = True
except ImportError:
    _GRPC_TO_HTTP = {}
    _HAS_GRPC = False


class GrpcInjector:
    def __init__(self, timeout: float = 5) -> None:
        self._timeout = timeout

    async def execute(
        self,
        target: str,
        service: str,
        method: str,
        payload: dict[str, Any],
        tls: bool = False,
        auth_headers: dict[str, str] | None = None,
    ) -> NormalizedResponse:
        if not _HAS_GRPC:
            return normalize_response(status_code=0, body="grpcio not installed")

        start = time.monotonic()
        try:
            creds = grpc.ssl_channel_credentials() if tls else None
            channel = (
                grpc.aio.secure_channel(target, creds)
                if tls
                else grpc.aio.insecure_channel(target)
            )
            metadata = list((auth_headers or {}).items())
            try:
                full_method = f"/{service}/{method}"
                response = await channel.unary_unary(
                    full_method,
                    request_serializer=_serialize_generic,
                    response_deserializer=_deserialize_generic,
                )(
                    payload,
                    metadata=metadata or None,
                    timeout=self._timeout,
                )
                elapsed = (time.monotonic() - start) * 1000
                return normalize_response(
                    status_code=200,
                    headers={"grpc-method": full_method},
                    body=str(response),
                    timing_ms=elapsed,
                )
            finally:
                await channel.close()
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            status_code = 0
            if _HAS_GRPC and isinstance(exc, grpc.RpcError):
                grpc_code = exc.code()
                status_code = _GRPC_TO_HTTP.get(grpc_code, 500)
            log.debug(
                "grpc_injector.failed",
                target=target,
                service=service,
                method=method,
                error=str(exc),
            )
            return normalize_response(
                status_code=status_code,
                body=str(exc),
                timing_ms=elapsed,
            )

    async def send_raw(
        self,
        req: NormalizedRequest,
        auth_headers: dict[str, str] | None = None,
    ) -> NormalizedResponse:
        parts = req.url.replace("grpc://", "").split("/", 2)
        target = parts[0] if parts else ""
        service = parts[1] if len(parts) > 1 else ""
        method = parts[2] if len(parts) > 2 else ""
        payload = req.body if isinstance(req.body, dict) else {}
        tls = False
        return await self.execute(
            target=target,
            service=service,
            method=method,
            payload=payload,
            tls=tls,
            auth_headers=auth_headers,
        )


def _serialize_generic(data: Any) -> bytes:
    import json

    return json.dumps(data).encode()


def _deserialize_generic(data: bytes) -> Any:
    import json

    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return data
