# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import structlog
from fastapi import WebSocket

log = structlog.get_logger()


class WebSocketManager:
    """Gère les connexions WebSocket actives et le broadcast."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        log.debug("ws.connected", total=len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        log.debug("ws.disconnected", total=len(self._connections))

    async def broadcast(self, data: dict) -> None:
        # Send to all connections concurrently so that one slow or unresponsive
        # client does not stall delivery to all others.
        connections = list(self._connections)
        if not connections:
            return
        results = await asyncio.gather(
            *[ws.send_json(data) for ws in connections],
            return_exceptions=True,
        )
        dead = {ws for ws, result in zip(connections, results) if isinstance(result, Exception)}
        if dead:
            async with self._lock:
                self._connections -= dead

    @property
    def connection_count(self) -> int:
        return len(self._connections)
