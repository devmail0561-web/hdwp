# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file in details.

"""SPACrawler: crawl SPA applications via Playwright.

Two modes:
- Proxy mode (proxy_port set): routes traffic through the HDWP MITM proxy.
- Autonomous mode (proxy_port=None): intercepts network requests directly via
  Playwright page.on("requestfinished"), emitting RawObservation events without
  needing an external proxy. Triggered automatically when the HTML crawler finds
  few endpoints (probable SPA).

Requires the optional [spa] extra: pip install hdwp[spa]
After install: playwright install chromium
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

log = structlog.get_logger()

_CAPTURED_RESOURCE_TYPES = frozenset({"xhr", "fetch", "document"})


class SPACrawler:
    """Crawl SPA applications (React, Vue, Angular, Next.js) via Playwright.

    In proxy mode: routes all browser traffic through the HDWP MITM proxy so
    the existing observation pipeline captures every network request.

    In autonomous mode: registers page.on("requestfinished") to capture XHR/fetch
    API calls directly and emit them as RawObservation events on the bus.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        session_id: str,
        proxy_port: int | None = None,
    ) -> None:
        self._proxy_port = proxy_port
        self._bus = bus
        self._session_id = session_id
        self._console_errors: list[dict] = []

    async def _on_requestfinished(self, request) -> None:  # type: ignore[no-untyped-def]
        if request.resource_type not in _CAPTURED_RESOURCE_TYPES:
            return
        try:
            response = await request.response()
            if response is None:
                return

            req_headers = dict(request.headers)
            resp_headers = dict(response.headers)
            body_bytes = await request.post_data_buffer() or b""
            body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else None

            try:
                resp_body = await response.json()
            except Exception:
                resp_body = None

            from hdwp.core.bus.events import OBSERVATION_RAW
            from hdwp.core.model.schemas import ObservationType, RawObservation
            from hdwp.core.observation.normalizer import normalize_request, normalize_response

            norm_req = normalize_request(
                method=request.method,
                url=request.url,
                headers=req_headers,
                body=body_str,
            )
            norm_resp = normalize_response(
                status_code=response.status,
                headers=resp_headers,
                body=resp_body,
            )
            obs = RawObservation(
                timestamp=datetime.now(UTC).isoformat(),
                source="active",
                type=ObservationType.HTTP,
                request=norm_req,
                response=norm_resp,
                session_id=self._session_id,
                tags=["role:anonymous", "source:spa_crawler"],
            )
            await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="spa_crawler")
        except Exception:
            pass

    async def crawl(self, seed_url: str) -> None:
        """Navigate seed_url via Playwright, capturing API traffic and console errors."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.debug("spa_crawler.playwright_not_installed",
                      hint="pip install hdwp[spa] && playwright install chromium")
            return

        try:
            async with async_playwright() as pw:
                launch_kwargs: dict = {
                    "args": [
                        "--ignore-certificate-errors",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ],
                }
                if self._proxy_port is not None:
                    launch_kwargs["proxy"] = {"server": f"http://127.0.0.1:{self._proxy_port}"}

                browser = await pw.chromium.launch(**launch_kwargs)
                try:
                    page = await browser.new_page()

                    if self._proxy_port is None:
                        page.on("requestfinished", self._on_requestfinished)

                    page.on("console", self._on_console)
                    page.on("pageerror", lambda err: self._console_errors.append(
                        {"t": "exception", "m": str(err)}
                    ))

                    try:
                        await page.goto(seed_url, wait_until="networkidle", timeout=15000)
                    except Exception:
                        try:
                            await page.goto(seed_url, wait_until="domcontentloaded", timeout=10000)
                        except Exception as exc:
                            log.warning("spa_crawler.navigation_failed",
                                        url=seed_url, error=str(exc))
                            return

                    from hdwp.core.bus.events import OBSERVATION_RAW
                    for err in self._console_errors[:50]:
                        await self._bus.emit(OBSERVATION_RAW, {
                            "type": "CONSOLE_LOG",
                            "session_id": self._session_id,
                            **err,
                        })

                    log.info("spa_crawler.done",
                             url=seed_url,
                             mode="autonomous" if self._proxy_port is None else "proxy",
                             console_errors=len(self._console_errors))
                finally:
                    await browser.close()

        except Exception as exc:
            log.warning("spa_crawler.error", error=str(exc))

    def _on_console(self, msg) -> None:  # type: ignore[no-untyped-def]
        if msg.type in ("error", "warning"):
            self._console_errors.append({"t": msg.type, "m": msg.text})
