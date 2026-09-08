# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import time

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus, HDWPEvent
from hdwp.core.bus.events import ALL_EVENT_TYPES
from hdwp.server.ws_manager import WebSocketManager

log = structlog.get_logger()

_IMMEDIATE: frozenset[str] = frozenset({
    "scan.completed",
    "scan.error",
    "auth.required",
    "finding.confirmed",
    "finding.refuted",
})

_THROTTLE_MS: dict[str, int] = {
    "ml.feedback":              300,
    "rl.transition":            300,
    "experiment.result":        150,
    "ml.oracle_verdict":        200,
    "diff.computed":            150,
    "ml.embedding_computed":    500,
    "ml.vuln_predicted":        300,
    "hypothesis.status_changed": 150,
}


class EventBridge:
    """Abonne le bus HDWP et broadcast tous les événements aux clients WebSocket."""

    def __init__(self, bus: AsyncEventBus, ws_manager: WebSocketManager, session_id: str = "") -> None:
        self._bus = bus
        self._ws_manager = ws_manager
        self._session_id = session_id
        self._last_sent: dict[str, float] = {}

    def attach(self) -> None:
        for event_type in ALL_EVENT_TYPES:
            async def _handler(event: HDWPEvent, et: str = event_type) -> None:
                try:
                    throttle = _THROTTLE_MS.get(et, 0)
                    if throttle > 0 and et not in _IMMEDIATE:
                        now = time.monotonic()
                        if now - self._last_sent.get(et, 0.0) < throttle / 1000.0:
                            return
                        self._last_sent[et] = now
                    await self._ws_manager.broadcast({
                        "type": et,
                        "session_id": self._session_id,
                        "source": event.source,
                        "ts": event.timestamp,
                        "payload": event.payload if isinstance(event.payload, dict) else {},
                    })
                except Exception as exc:
                    log.warning("event_bridge.broadcast_error", event_type=et, error=str(exc))
            self._bus.on(event_type, _handler)
