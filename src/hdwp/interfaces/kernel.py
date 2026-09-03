# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.context.loader import EngineContext
    from hdwp.core.engine import HDWPEngine


class KernelBuilder:
    """API fluent pour construire un HDWPEngine.

    Exemple :
        engine = await (
            KernelBuilder()
            .with_context(ctx)
            .with_bus(bus)
            .with_db_url("sqlite+aiosqlite:///evidence.db")
            .build()
        )
    """

    def __init__(self) -> None:
        self._context: EngineContext | None = None
        self._bus: AsyncEventBus | None = None
        self._db_url: str | None = None
        self._plugin_ids: list[str] | None = None

    def with_context(self, ctx: EngineContext) -> KernelBuilder:
        self._context = ctx
        return self

    def with_bus(self, bus: AsyncEventBus) -> KernelBuilder:
        self._bus = bus
        return self

    def with_db_url(self, url: str) -> KernelBuilder:
        self._db_url = url
        return self

    def with_plugin_ids(self, ids: list[str]) -> KernelBuilder:
        self._plugin_ids = ids
        return self

    async def build(self) -> HDWPEngine:
        """Construit et retourne l'engine câblé."""
        if self._context is None:
            raise ValueError("KernelBuilder : context requis (appeler .with_context())")
        from hdwp.core.bus.event_bus import AsyncEventBus as _Bus
        from hdwp.core.engine import HDWPEngine
        return await HDWPEngine.create_from_context(
            self._context,
            self._bus or _Bus(),
            db_url=self._db_url,
            plugin_ids=self._plugin_ids,
        )
