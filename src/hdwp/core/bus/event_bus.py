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
        self._stream_handlers: dict[str, list[Callable[..., Any]]] = {}

    @property
    def history(self) -> list[HDWPEvent]:
        return list(self._history)

    async def emit(self, event_type: str, payload: Any, source: str = "") -> None:
        event = HDWPEvent(type=event_type, source=source, payload=payload)
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]
        logger.debug("event.emitted", event_type=event_type, source=source)

        for handler in self._stream_handlers.get(event_type, []):
            try:
                await handler(event)
            except Exception as exc:  # noqa: BLE001
                logger.warning("event.stream_handler_exception", error=str(exc))

        self._emitter.emit(event_type, event)

    def on(self, event_type: str, handler: Callable[..., Any], *, mode: str = "batch") -> None:
        VALID_MODES = {"batch", "stream"}
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}', must be one of {VALID_MODES}")

        if mode == "stream":
            if not asyncio.iscoroutinefunction(handler):
                raise TypeError(f"Stream handlers must be async coroutines, got {type(handler).__name__}")
            self._stream_handlers.setdefault(event_type, []).append(handler)
            return

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

        # Support both batch and stream handlers
        self._emitter.once(event_type, _on_event)

        # If only stream handlers exist, register temporary handler to capture event
        if event_type in self._stream_handlers and event_type not in dict(self._emitter._events):
            async def _stream_capture(event: HDWPEvent) -> None:
                if not future.done():
                    future.set_result(event)
            self._stream_handlers[event_type].append(_stream_capture)
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            finally:
                if _stream_capture in self._stream_handlers.get(event_type, []):
                    self._stream_handlers[event_type].remove(_stream_capture)

        return await asyncio.wait_for(future, timeout=timeout)

    async def drain(self) -> None:
        max_iterations = 100  # Prevent infinite loops from recursive handlers
        iteration = 0

        while self._pending and iteration < max_iterations:
            iteration += 1
            tasks = [t for t in self._pending if not t.done()]
            if not tasks:
                self._pending.clear()
                break

            # Snapshot current pending size to detect runaway growth
            initial_size = len(self._pending)

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

            # Warn if pending queue is growing unbounded
            if len(self._pending) > initial_size * 2:
                logger.warning(
                    "event.drain_queue_growing",
                    initial=initial_size,
                    current=len(self._pending),
                    iteration=iteration,
                )

        if iteration >= max_iterations and self._pending:
            logger.error(
                "event.drain_max_iterations",
                pending_count=len(self._pending),
                msg="Drain loop exceeded max iterations, possible recursive handler",
            )

        await asyncio.sleep(0)
