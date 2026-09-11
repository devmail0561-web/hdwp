# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import Any

import httpx

from hdwp.core.model.schemas import NormalizedRequest, NormalizedResponse
from hdwp.core.observation.normalizer import normalize_response


async def dispatch_send(
    client: httpx.AsyncClient,
    req: NormalizedRequest,
    auth_headers: dict[str, str] | None = None,
) -> httpx.Response | NormalizedResponse:
    if req.url.startswith(("ws://", "wss://")):
        from hdwp.core.experiment.ws_injector import WebSocketInjector

        return await WebSocketInjector().send_raw(
            req.url,
            payload=req.body,
            auth_headers=auth_headers,
        )
    if req.url.startswith("grpc://"):
        from hdwp.core.experiment.grpc_injector import GrpcInjector

        return await GrpcInjector().send_raw(req, auth_headers=auth_headers)
    return await send_http(client, req)


async def send_http(
    client: httpx.AsyncClient, req: NormalizedRequest,
) -> httpx.Response:
    headers: dict[str, Any] = {
        k: v for k, v in req.headers.items() if v != "[REDACTED]"
    }
    if req.raw_body_override is not None:
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            content=req.raw_body_override,
        )
    if isinstance(req.body, dict):
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            json=req.body,
        )
    if isinstance(req.body, str):
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            content=req.body.encode(),
        )
    return await client.request(
        method=req.method,
        url=req.url,
        headers=headers,
    )
