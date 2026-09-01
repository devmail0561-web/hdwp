# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import httpx
import pytest
import respx

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW, HDWPEvent
from hdwp.core.context.config_schema import (
    CredentialConfig,
    HDWPContextConfig,
    OptionsConfig,
    RoleConfig,
    ScopeConfig,
    TargetConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.observation.active_crawler import ActiveCrawler, extract_links


def _make_context(
    base_url: str = "http://test.local",
    allow_write: bool = False,
    roles: list[RoleConfig] | None = None,
) -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url=base_url, name="Test"),
        scope=ScopeConfig(include=[f"{base_url}", f"{base_url}/*"]),
        roles=roles or [RoleConfig(name="anonymous")],
        options=OptionsConfig(allow_write=allow_write, max_requests_per_minute=6000),
    )
    return EngineContext(config=config, base_url=base_url, session_id="test-session")


def _make_crawler(
    bus: AsyncEventBus,
    context: EngineContext | None = None,
    max_depth: int = 3,
    max_pages: int = 100,
) -> ActiveCrawler:
    ctx = context or _make_context()
    scope_guard = ScopeGuard(ctx)
    rate_limiter = TokenBucket(rate=1000.0, capacity=1000)
    return ActiveCrawler(
        bus=bus,
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        roles=ctx.config.roles,
        session_id=ctx.session_id,
        max_depth=max_depth,
        max_pages=max_pages,
    )


# ── link extraction ──────────────────────────────────────


def test_extract_links_from_html() -> None:
    html = """
    <html>
    <body>
        <a href="/page1">Page 1</a>
        <a href="/page2">Page 2</a>
        <form action="/submit"></form>
    </body>
    </html>
    """
    links = extract_links(html, "http://test.local")
    assert "http://test.local/page1" in links
    assert "http://test.local/page2" in links
    assert "http://test.local/submit" in links


def test_extract_links_ignores_javascript() -> None:
    html = '<a href="javascript:void(0)">Click</a><a href="mailto:a@b.com">Mail</a>'
    links = extract_links(html, "http://test.local")
    assert links == []


def test_extract_links_resolves_relative() -> None:
    html = '<a href="sub/page">Page</a>'
    links = extract_links(html, "http://test.local/dir/")
    assert "http://test.local/dir/sub/page" in links


# ── crawler ──────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_crawler_emits_observations() -> None:
    respx.get("http://test.local").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Hello</body></html>",
            headers={"content-type": "text/html"},
        )
    )
    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) >= 1
    assert received[0].type == OBSERVATION_RAW


@pytest.mark.asyncio
@respx.mock
async def test_crawler_follows_links() -> None:
    respx.get("http://test.local").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/page2">Link</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    respx.get("http://test.local/page2").mock(
        return_value=httpx.Response(200, text="<html>Page 2</html>", headers={"content-type": "text/html"})
    )

    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) == 2


@pytest.mark.asyncio
@respx.mock
async def test_crawler_respects_scope() -> None:
    respx.get("http://test.local").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="http://evil.com/hack">Evil</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    respx.get("http://evil.com/hack").mock(
        return_value=httpx.Response(200, text="Evil")
    )

    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) == 1


@pytest.mark.asyncio
@respx.mock
async def test_crawler_respects_max_depth() -> None:
    respx.get("http://test.local").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/d1">D1</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    respx.get("http://test.local/d1").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/d2">D2</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    respx.get("http://test.local/d2").mock(
        return_value=httpx.Response(200, text="<html>Deep</html>", headers={"content-type": "text/html"})
    )

    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus, max_depth=1)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) == 2


@pytest.mark.asyncio
@respx.mock
async def test_crawler_respects_max_pages() -> None:
    for i in range(10):
        next_link = f'<a href="/p{i+1}">Next</a>' if i < 9 else ""
        respx.get(f"http://test.local/p{i}").mock(
            return_value=httpx.Response(
                200,
                text=f"<html>{next_link}</html>",
                headers={"content-type": "text/html"},
            )
        )
    respx.get("http://test.local").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/p0">Start</a></html>',
            headers={"content-type": "text/html"},
        )
    )

    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus, max_pages=3)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) == 3


@pytest.mark.asyncio
@respx.mock
async def test_crawler_with_bearer_auth() -> None:
    respx.get("http://test.local").mock(
        return_value=httpx.Response(200, text='{"ok": true}', headers={"content-type": "application/json"})
    )

    roles = [
        RoleConfig(
            name="user_a",
            credentials=CredentialConfig(type="bearer", token="my-token"),
        )
    ]
    ctx = _make_context(roles=roles)
    bus = AsyncEventBus()
    received: list[HDWPEvent] = []

    async def handler(event: HDWPEvent) -> None:
        received.append(event)

    bus.on(OBSERVATION_RAW, handler)
    crawler = _make_crawler(bus, context=ctx)
    await crawler.crawl("http://test.local")
    await bus.drain()

    assert len(received) == 1
    obs = received[0].payload
    # Payload is a dict (model_dump) since the bus standardises on dicts
    tags = obs["tags"] if isinstance(obs, dict) else obs.tags
    assert "role:user_a" in tags
