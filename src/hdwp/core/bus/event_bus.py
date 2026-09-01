# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import structlog
from pyee.asyncio import AsyncIOEventEmitter

from hdwp.core.bus.events import HDWPEvent

logger = structlog.get_logger()


class AsyncEventBus:
    def __init__(self, max_history: int = 1000) -> None:
        self._emitter = AsyncIOEventEmitter()
        self._max_history = max_history
        self._history: list[HDWPEvent] = []
        self._pending: list[asyncio.Task[None]] = []

    @property
    def history(self) -> list[HDWPEvent]:
        return list(self._history)

    async def emit(self, event_type: str, payload: Any, source: str = "") -> None:
        event = HDWPEvent(type=event_type, source=source, payload=payload)
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]
        logger.debug("event.emitted", event_type=event_type, source=source)
        self._emitter.emit(event_type, event)

    def on(self, event_type: str, handler: Callable[..., Any]) -> None:
        if asyncio.iscoroutinefunction(handler):
            original = handler

            def _sync_wrapper(event: HDWPEvent) -> None:
                task = asyncio.ensure_future(original(event))
                self._pending.append(task)

            self._emitter.on(event_type, _sync_wrapper)
        else:
            self._emitter.on(event_type, handler)

    async def wait_for(self, event_type: str, timeout: float = 5.0) -> HDWPEvent:
        future: asyncio.Future[HDWPEvent] = asyncio.get_running_loop().create_future()

        def _on_event(event: HDWPEvent) -> None:
            if not future.done():
                future.set_result(event)

        self._emitter.once(event_type, _on_event)
        return await asyncio.wait_for(future, timeout=timeout)

    async def drain(self) -> None:
        while self._pending:
            tasks = [t for t in self._pending if not t.done()]
            if not tasks:
                self._pending.clear()
                break
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(
                        "event.handler_exception",
                        task_index=i,
                        error=str(result),
                        exception_type=type(result).__name__,
                    )
            self._pending = [t for t in self._pending if not t.done()]
        await asyncio.sleep(0)
