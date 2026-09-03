# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

# Événements que les plugins peuvent émettre
PLUGIN_ALLOWED_EMIT = frozenset({"observation.raw"})


class PluginBusView:
    """Vue restreinte du bus pour les plugins.

    Les plugins peuvent s'abonner à tous les événements,
    mais ne peuvent émettre que 'observation.raw' ou 'plugin.*'.
    ADR-002 : interdit 'finding.confirmed' depuis un plugin.
    """

    def __init__(self, bus: AsyncEventBus, plugin_id: str) -> None:
        self._bus = bus
        self._plugin_id = plugin_id

    def on(self, event_type: str, handler: Callable[..., Any]) -> None:
        """S'abonner à un événement du bus."""
        self._bus.on(event_type, handler)

    async def emit(self, event_type: str, payload: Any) -> None:
        """Émettre un événement. Restreint à 'observation.raw' et 'plugin.*'."""
        if event_type not in PLUGIN_ALLOWED_EMIT and not event_type.startswith("plugin."):
            raise PermissionError(
                f"Plugin '{self._plugin_id}' ne peut pas émettre '{event_type}'. "
                "Autorisé : 'observation.raw' et 'plugin.*'."
            )
        await self._bus.emit(
            event_type, payload, source=f"plugin.{self._plugin_id}"
        )
