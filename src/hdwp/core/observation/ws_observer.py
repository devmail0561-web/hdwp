# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import structlog
import websockets
import websockets.exceptions

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.model.schemas import (
    NormalizedResponse,
    ObservationType,
    RawObservation,
)

log = structlog.get_logger()


class WebSocketObserver:
    def __init__(
        self,
        bus: AsyncEventBus,
        session_id: str,
        timeout: float = 5,
        max_messages: int = 10,
    ) -> None:
        self._bus = bus
        self._session_id = session_id
        self._timeout = timeout
        self._max_messages = max_messages

    async def observe(
        self,
        ws_urls: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> None:
        for url in ws_urls:
            try:
                await self._observe_one(url, auth_headers)
            except (OSError, websockets.exceptions.WebSocketException) as exc:
                log.debug("ws_observer.connect_failed", url=url, error=str(exc))

    async def _observe_one(
        self,
        url: str,
        auth_headers: dict[str, str] | None,
    ) -> None:
        async with websockets.connect(
            url,
            open_timeout=self._timeout,
            additional_headers=auth_headers or {},
        ) as ws:
            subprotocol = ws.subprotocol
            received = 0
            for _ in range(self._max_messages):
                try:
                    msg = await asyncio.wait_for(ws.recv(), self._timeout)
                except asyncio.TimeoutError:
                    break
                received += 1
                fmt = _detect_format(msg)
                body = msg if isinstance(msg, str) else None
                obs = RawObservation(
                    timestamp=datetime.now(UTC).isoformat(),
                    source="active",
                    type=ObservationType.WS,
                    session_id=self._session_id,
                    response=NormalizedResponse(status_code=101, body=body),
                    artefact={
                        "ws_url": url,
                        "format": fmt,
                        "subprotocol": subprotocol,
                        "is_binary": isinstance(msg, bytes),
                        "msg_index": received,
                    },
                )
                await self._bus.emit(
                    OBSERVATION_RAW, obs.model_dump(), source="ws_observer",
                )

            # Probe echo
            try:
                await ws.send('{"type":"ping"}')
                probe_msg = await asyncio.wait_for(ws.recv(), self._timeout)
                probe_fmt = _detect_format(probe_msg)
                probe_body = probe_msg if isinstance(probe_msg, str) else None
                obs = RawObservation(
                    timestamp=datetime.now(UTC).isoformat(),
                    source="active",
                    type=ObservationType.WS,
                    session_id=self._session_id,
                    response=NormalizedResponse(status_code=101, body=probe_body),
                    artefact={
                        "ws_url": url,
                        "format": probe_fmt,
                        "subprotocol": subprotocol,
                        "is_binary": isinstance(probe_msg, bytes),
                        "probe": True,
                    },
                    tags=["ws:probe"],
                )
                await self._bus.emit(
                    OBSERVATION_RAW, obs.model_dump(), source="ws_observer",
                )
            except (asyncio.TimeoutError, websockets.exceptions.WebSocketException):
                pass


def _detect_format(msg: str | bytes) -> str:
    if isinstance(msg, bytes):
        if len(msg) > 0 and msg[0] in range(0x80, 0x90):
            return "msgpack"
        return "binary"
    try:
        json.loads(msg)
        return "json"
    except (ValueError, TypeError):
        return "text"
