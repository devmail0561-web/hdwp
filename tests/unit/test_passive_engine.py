# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.model.schemas import (
    NormalizedRequest,
    NormalizedResponse,
    ObservationType,
    RawObservation,
)
from hdwp.core.oracle.passive_engine import PassiveFindingEngine


def _make_repo() -> MagicMock:
    repo = MagicMock()
    repo.save_finding = AsyncMock()
    return repo


def _obs(url: str = "http://t/page", tags: list[str] | None = None, body: str | None = None) -> dict:
    return RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url=url),
        response=NormalizedResponse(status_code=200, body=body),
        session_id="s1",
        tags=tags or [],
    ).model_dump()


@pytest.mark.asyncio
async def test_missing_hsts_generates_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    engine = PassiveFindingEngine(bus, repo)

    received = []
    bus.on("finding.confirmed", lambda e: received.append(e))

    await bus.emit("observation.raw", _obs(tags=["missing:HSTS"]), source="test")
    await bus.drain()

    assert repo.save_finding.called
    finding = repo.save_finding.call_args[0][0]
    assert finding.owasp_category == "A05:2021"
    assert finding.cwe_id == "CWE-319"
    assert finding.severity == "LOW"


@pytest.mark.asyncio
async def test_missing_csp_generates_medium_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    await bus.emit("observation.raw", _obs(tags=["missing:CSP"]), source="test")
    await bus.drain()

    finding = repo.save_finding.call_args[0][0]
    assert finding.cwe_id == "CWE-693"
    assert finding.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_server_disclosure_generates_info_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    await bus.emit("observation.raw", _obs(tags=["server:nginx/1.18"]), source="test")
    await bus.drain()

    finding = repo.save_finding.call_args[0][0]
    assert finding.cwe_id == "CWE-200"
    assert finding.severity == "INFO"
    assert "nginx" in finding.proof["reproduction_steps"][1]


@pytest.mark.asyncio
async def test_cookie_missing_httponly_generates_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    await bus.emit("observation.raw", _obs(tags=["cookie:missing-httponly"]), source="test")
    await bus.drain()

    finding = repo.save_finding.call_args[0][0]
    assert finding.cwe_id == "CWE-1004"


@pytest.mark.asyncio
async def test_cookie_missing_secure_generates_medium_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    await bus.emit("observation.raw", _obs(tags=["cookie:missing-secure"]), source="test")
    await bus.drain()

    finding = repo.save_finding.call_args[0][0]
    assert finding.severity == "MEDIUM"
    assert finding.cwe_id == "CWE-614"


@pytest.mark.asyncio
async def test_stack_trace_python_generates_finding() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    body = "Traceback (most recent call last):\n  File app.py line 42"
    await bus.emit("observation.raw", _obs(body=body), source="test")
    await bus.drain()

    finding = repo.save_finding.call_args[0][0]
    assert finding.cwe_id == "CWE-209"
    assert finding.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_deduplication_same_tag_same_endpoint() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    obs = _obs(url="http://t/page", tags=["missing:HSTS"])
    await bus.emit("observation.raw", obs, source="test")
    await bus.emit("observation.raw", obs, source="test")
    await bus.drain()

    # Only saved once
    assert repo.save_finding.call_count == 1


@pytest.mark.asyncio
async def test_deduplication_same_tag_different_endpoint_both_saved() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    await bus.emit("observation.raw", _obs(url="http://t/page1", tags=["missing:HSTS"]), source="test")
    await bus.emit("observation.raw", _obs(url="http://t/page2", tags=["missing:HSTS"]), source="test")
    await bus.drain()

    assert repo.save_finding.call_count == 2


@pytest.mark.asyncio
async def test_no_finding_for_clean_response() -> None:
    bus = AsyncEventBus()
    repo = _make_repo()
    PassiveFindingEngine(bus, repo)

    # Tags only contain role and a present security header (no missing: prefix)
    await bus.emit("observation.raw", _obs(tags=["role:anonymous"]), source="test")
    await bus.drain()

    assert not repo.save_finding.called
