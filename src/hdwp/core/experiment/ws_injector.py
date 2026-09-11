# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
import time

import structlog
import websockets
import websockets.exceptions

from hdwp.core.model.schemas import NormalizedResponse
from hdwp.core.observation.normalizer import normalize_response

log = structlog.get_logger()


class WebSocketInjector:
    def __init__(self, timeout: float = 5) -> None:
        self._timeout = timeout

    async def execute(
        self,
        ws_url: str,
        payload: str,
        auth_headers: dict[str, str] | None = None,
    ) -> NormalizedResponse:
        start = time.monotonic()
        try:
            async with websockets.connect(
                ws_url,
                open_timeout=self._timeout,
                additional_headers=auth_headers or {},
            ) as ws:
                await ws.send(payload)
                response = await asyncio.wait_for(ws.recv(), self._timeout)
                elapsed = (time.monotonic() - start) * 1000
                body = response if isinstance(response, str) else repr(response)
                return normalize_response(
                    status_code=101,
                    headers={},
                    body=body,
                    timing_ms=elapsed,
                )
        except (OSError, websockets.exceptions.WebSocketException, asyncio.TimeoutError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            log.debug("ws_injector.failed", url=ws_url, error=str(exc))
            return normalize_response(
                status_code=0,
                headers={},
                body=None,
                timing_ms=elapsed,
            )

    async def send_raw(
        self,
        ws_url: str,
        payload: str | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> NormalizedResponse:
        return await self.execute(
            ws_url,
            payload=payload or "",
            auth_headers=auth_headers,
        )
