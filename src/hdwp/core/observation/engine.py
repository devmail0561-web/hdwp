# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.observation.active_crawler import ActiveCrawler

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol

log = structlog.get_logger()


class ObservationEngine:
    def __init__(
        self,
        bus: AsyncEventBus,
        context: EngineContext,
        scope_guard: ScopeGuard,
        llm_layer: LLMLayerProtocol | None = None,
        proxy_url: str | None = None,
    ) -> None:
        self._bus = bus
        self._context = context
        self._scope_guard = scope_guard
        self._running = False
        self._proxy: object | None = None
        self._llm_layer = llm_layer
        self._proxy_url = proxy_url
        self._crawler: ActiveCrawler | None = None
        self._crawl_task: asyncio.Task | None = None
        self._model_accessor: object | None = None  # injecté par HDWPEngine pour rescan

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
        discovery_delay = min(1.0, max(0.0, 60.0 / rate_limiter.max_rate - 1.0)) if rate_limiter.max_rate > 0 else 1.0
        spec = await auto_discover_spec(self._context.base_url, delay_between_requests=discovery_delay)
        if spec:
            seeded = await seed_from_openapi_spec(self._bus, self._context, spec)
            log.info("observation_engine.openapi_auto_seeded", observations=seeded)

        # 2. Crawl HTML (et extraction JS)
        self._crawler = ActiveCrawler(
            bus=self._bus,
            scope_guard=self._scope_guard,
            rate_limiter=rate_limiter,
            roles=self._context.config.roles,
            session_id=self._context.session_id,
            llm_layer=self._llm_layer,
            proxy_url=self._proxy_url,
            emit_observations=(self._proxy_url is None),
        )
        self._crawl_task = asyncio.ensure_future(self._crawler.crawl(self._context.base_url))
        with contextlib.suppress(asyncio.CancelledError):
            await self._crawl_task
        self._crawl_task = None

        # SPA crawl via Playwright — only when proxy is active (port known)
        # Routes browser traffic through the HDWP MITM proxy automatically
        if self._proxy_url:
            try:
                from urllib.parse import urlparse as _urlparse
                from hdwp.core.observation.spa_crawler import SPACrawler
                port = _urlparse(self._proxy_url).port or 8080
                spa = SPACrawler(
                    proxy_port=port,
                    bus=self._bus,
                    session_id=self._context.session_id,
                )
                await spa.crawl(self._context.base_url)
            except Exception as exc:
                log.debug("spa_crawler.skipped", reason=str(exc))

        self._running = False
        log.info("observation_engine.done")

    async def stop(self) -> None:
        self._running = False
        if self._crawl_task and not self._crawl_task.done():
            self._crawl_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._crawl_task
            log.info("observation_engine.crawl_cancelled")

    async def rescan_known_endpoints(self) -> None:
        """Re-émet des observations pour les endpoints déjà connus du modèle.

        Utilisé en mode continu pour détecter les changements d'état après des exploits
        confirmés ou des modifications de comportement entre itérations.
        Ne crawle pas de nouveaux liens — seulement les endpoints déjà dans le modèle.
        """
        if self._model_accessor is None:
            return
        model = self._model_accessor()  # type: ignore[operator]
        if model is None:
            return

        from hdwp.core.http_client import build_client
        from hdwp.core.observation.normalizer import normalize_request, normalize_response

        rate_limiter = TokenBucket.from_rpm(
            self._context.config.options.max_requests_per_minute
        )

        endpoints_to_scan = model.endpoints[:20]  # cap pour limiter le trafic
        for ep in endpoints_to_scan:
            if not self._scope_guard.check(ep.path, "GET").name == "ALLOWED":
                continue
            url = self._context.base_url.rstrip("/") + ep.path
            for role in self._context.config.roles:
                await rate_limiter.acquire()
                try:
                    from hdwp.core.observation.active_crawler import _build_auth_headers
                    async with build_client(timeout=10.0, proxy_url=self._proxy_url) as client:
                        client.headers.update(_build_auth_headers(role.credentials) or {})
                        resp = await client.get(url, follow_redirects=False)
                        norm_req = normalize_request(
                            method="GET", url=url,
                            headers=dict(client.headers), body=None,
                            query_params={}, path_params={},
                        )
                        norm_resp = normalize_response(resp)
                        from hdwp.core.model.schemas import RawObservation
                        obs = RawObservation(
                            request=norm_req,
                            response=norm_resp,
                            tags=[f"role:{role.name}", "rescan:true"],
                            session_id=self._context.session_id,
                        )
                        from hdwp.core.bus.events import OBSERVATION_RAW
                        await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="rescan")
                except Exception as exc:
                    log.debug("rescan.endpoint_failed", url=url, error=str(exc))

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

    @property
    def collected_script_urls(self) -> frozenset[str]:
        return self._crawler.script_urls if self._crawler else frozenset()

    @property
    def collected_script_contents(self) -> dict[str, str]:
        return self._crawler.script_contents if self._crawler else {}

    @property
    def collected_script_pages(self) -> dict[str, list[str]]:
        return self._crawler.script_pages if self._crawler else {}
