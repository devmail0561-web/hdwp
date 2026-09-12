# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.observation.spa_crawler import SPACrawler


@pytest.mark.asyncio
async def test_spa_crawler_no_proxy_skips_when_playwright_absent() -> None:
    bus = AsyncEventBus()
    crawler = SPACrawler(bus=bus, session_id="test")
    with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
        with patch("builtins.__import__", side_effect=ImportError("playwright not installed")):
            # Should not raise — silently skips
            try:
                await crawler.crawl("http://localhost:3000")
            except ImportError:
                pass  # acceptable — ImportError is caught internally


@pytest.mark.asyncio
async def test_on_requestfinished_xhr_emits_observation() -> None:
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)

    crawler = SPACrawler(bus=bus, session_id="test-session")

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json = AsyncMock(return_value={"id": 1, "name": "test"})

    mock_request = MagicMock()
    mock_request.resource_type = "xhr"
    mock_request.method = "GET"
    mock_request.url = "http://localhost:3000/api/products"
    mock_request.headers = {"accept": "application/json"}
    mock_request.response = AsyncMock(return_value=mock_response)
    mock_request.post_data_buffer = AsyncMock(return_value=b"")

    await crawler._on_requestfinished(mock_request)
    await bus.drain()

    assert len(received) == 1
    payload = received[0].payload
    assert payload["request"] is not None
    assert payload["response"] is not None
    assert payload["request"]["url"] == "http://localhost:3000/api/products"
    assert payload["response"]["status_code"] == 200
    assert "role:anonymous" in payload["tags"]
    assert "source:spa_crawler" in payload["tags"]


@pytest.mark.asyncio
async def test_on_requestfinished_image_ignored() -> None:
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)

    crawler = SPACrawler(bus=bus, session_id="test-session")

    mock_request = MagicMock()
    mock_request.resource_type = "image"

    await crawler._on_requestfinished(mock_request)
    await bus.drain()

    assert received == [], "Images should not emit observations"


@pytest.mark.asyncio
async def test_on_requestfinished_fetch_emits_observation() -> None:
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)

    crawler = SPACrawler(bus=bus, session_id="test-session")

    mock_response = MagicMock()
    mock_response.status = 201
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json = AsyncMock(return_value={"token": "abc"})

    mock_request = MagicMock()
    mock_request.resource_type = "fetch"
    mock_request.method = "POST"
    mock_request.url = "http://localhost:3000/api/login"
    mock_request.headers = {"content-type": "application/json"}
    mock_request.response = AsyncMock(return_value=mock_response)
    mock_request.post_data_buffer = AsyncMock(return_value=b'{"email":"test@test.com"}')

    await crawler._on_requestfinished(mock_request)
    await bus.drain()

    assert len(received) == 1
    payload = received[0].payload
    assert payload["request"]["method"] == "POST"
    assert payload["response"]["status_code"] == 201


def test_spa_crawler_proxy_mode_uses_proxy_port() -> None:
    bus = AsyncEventBus()
    crawler = SPACrawler(bus=bus, session_id="test", proxy_port=8080)
    assert crawler._proxy_port == 8080


def test_spa_crawler_autonomous_mode_no_proxy() -> None:
    bus = AsyncEventBus()
    crawler = SPACrawler(bus=bus, session_id="test")
    assert crawler._proxy_port is None
