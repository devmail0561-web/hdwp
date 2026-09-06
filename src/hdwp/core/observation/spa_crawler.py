# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SPACrawler: crawl SPA applications via Playwright routed through the HDWP MITM proxy.

Requires the optional [spa] extra: pip install hdwp[spa]
After install: playwright install chromium
"""
from __future__ import annotations

import structlog
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

log = structlog.get_logger()


class SPACrawler:
    """Crawl SPA applications (React, Vue, Angular, Next.js) via Playwright.

    Routes all browser traffic through the HDWP MITM proxy so the existing
    observation pipeline captures every network request automatically.
    Additionally captures console errors and warnings from the browser.
    """

    def __init__(self, proxy_port: int, bus: AsyncEventBus, session_id: str) -> None:
        self._proxy_url = f"http://127.0.0.1:{proxy_port}"
        self._bus = bus
        self._session_id = session_id
        self._console_errors: list[dict] = []

    async def crawl(self, seed_url: str) -> None:
        """Navigate seed_url via Playwright, capturing post-JS DOM and console errors.

        All network requests from the browser are intercepted by the HDWP proxy
        and observed by the existing ObservationEngine pipeline.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.debug("spa_crawler.playwright_not_installed",
                      hint="pip install hdwp[spa] && playwright install chromium")
            return

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    proxy={"server": self._proxy_url},
                    args=[
                        "--ignore-certificate-errors",  # accept HDWP self-signed CA
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ],
                )
                try:
                    page = await browser.new_page()
                    page.on("console", self._on_console)
                    page.on("pageerror", lambda err: self._console_errors.append(
                        {"t": "exception", "m": str(err)}
                    ))

                    # Navigate — networkidle waits for all requests to finish
                    try:
                        await page.goto(seed_url, wait_until="networkidle", timeout=15000)
                    except Exception:
                        # Fallback: domcontentloaded is faster but misses late XHR
                        try:
                            await page.goto(seed_url, wait_until="domcontentloaded", timeout=10000)
                        except Exception as exc:
                            log.warning("spa_crawler.navigation_failed",
                                        url=seed_url, error=str(exc))
                            return

                    # Emit captured console errors on the event bus
                    from hdwp.core.bus.events import OBSERVATION_RAW
                    for err in self._console_errors[:50]:
                        await self._bus.emit(OBSERVATION_RAW, {
                            "type": "CONSOLE_LOG",
                            "session_id": self._session_id,
                            **err,
                        })

                    log.info("spa_crawler.done",
                             url=seed_url,
                             console_errors=len(self._console_errors))
                finally:
                    await browser.close()

        except Exception as exc:
            log.warning("spa_crawler.error", error=str(exc))

    def _on_console(self, msg) -> None:  # type: ignore[no-untyped-def]
        if msg.type in ("error", "warning"):
            self._console_errors.append({"t": msg.type, "m": msg.text})
