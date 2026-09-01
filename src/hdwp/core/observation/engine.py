# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.observation.active_crawler import ActiveCrawler

log = structlog.get_logger()


class ObservationEngine:
    def __init__(
        self,
        bus: AsyncEventBus,
        context: EngineContext,
        scope_guard: ScopeGuard,
    ) -> None:
        self._bus = bus
        self._context = context
        self._scope_guard = scope_guard
        self._running = False
        self._proxy: object | None = None

    async def start(self) -> None:
        self._running = True
        log.info("observation_engine.start", base_url=self._context.base_url)

        # Rate limiter for all discovery requests
        rate_limiter = TokenBucket.from_rpm(
            self._context.config.options.max_requests_per_minute
        )

        # 1. Tenter la découverte automatique de spec OpenAPI AVANT le crawl HTML.
        #    (sauf si déjà seedée via seed_from_spec() avant start())
        from hdwp.core.observation.openapi_seeder import auto_discover_spec, seed_from_openapi_spec
        discovery_delay = max(0.0, 60.0 / rate_limiter.max_rate - 1.0) if rate_limiter.max_rate > 0 else 1.0
        spec = await auto_discover_spec(self._context.base_url, delay_between_requests=discovery_delay)
        if spec:
            seeded = await seed_from_openapi_spec(self._bus, self._context, spec)
            log.info("observation_engine.openapi_auto_seeded", observations=seeded)

        # 2. Crawl HTML (et extraction JS)
        crawler = ActiveCrawler(
            bus=self._bus,
            scope_guard=self._scope_guard,
            rate_limiter=rate_limiter,
            roles=self._context.config.roles,
            session_id=self._context.session_id,
        )
        await crawler.crawl(self._context.base_url)
        self._running = False
        log.info("observation_engine.done")

    async def stop(self) -> None:
        self._running = False

    async def start_passive(self, port: int = 8080, role_name: str = "anonymous") -> None:
        """Démarre le proxy passif (nécessite mitmproxy : pip install hdwp[proxy])."""
        from hdwp.core.observation.proxy_capture import ProxyCapture
        self._proxy = ProxyCapture(
            bus=self._bus,
            scope_guard=self._scope_guard,
            session_id=self._context.session_id,
            port=port,
            role_name=role_name,
        )
        log.info("observation_engine.passive_start", port=port)
        await self._proxy.start()  # type: ignore[attr-defined]

    async def stop_passive(self) -> None:
        """Arrête le proxy passif."""
        if self._proxy is not None:
            await self._proxy.stop()  # type: ignore[attr-defined]

    async def seed_from_spec(self) -> int:
        """Pré-alimente le modèle depuis une spec OpenAPI ou des endpoints manuels."""
        from hdwp.core.observation.openapi_seeder import seed_from_openapi
        return await seed_from_openapi(self._bus, self._context)

    @property
    def running(self) -> bool:
        return self._running
