# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import structlog
from hdwp.core.bus.event_bus import AsyncEventBus, HDWPEvent
from hdwp.core.bus.events import ALL_EVENT_TYPES
from hdwp.server.ws_manager import WebSocketManager

log = structlog.get_logger()


class EventBridge:
    """Abonne le bus HDWP et broadcast tous les événements aux clients WebSocket."""

    def __init__(self, bus: AsyncEventBus, ws_manager: WebSocketManager) -> None:
        self._bus = bus
        self._ws_manager = ws_manager

    def attach(self) -> None:
        """Enregistre un handler async pour chaque type d'événement.

        Pattern `et=event_type` : capture la valeur courante à chaque
        itération — évite le bug classique de late-binding en Python.
        """
        for event_type in ALL_EVENT_TYPES:
            async def _handler(event: HDWPEvent, et: str = event_type) -> None:
                try:
                    await self._ws_manager.broadcast({
                        "type": et,
                        "source": event.source,
                        "ts": event.timestamp,
                        "payload": event.payload if isinstance(event.payload, dict) else {},
                    })
                except Exception as exc:
                    log.warning("event_bridge.broadcast_error", event_type=et, error=str(exc))
            self._bus.on(event_type, _handler)
