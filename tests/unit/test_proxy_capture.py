# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.context.config_schema import HDWPContextConfig, OptionsConfig, ScopeConfig, TargetConfig
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.observation.proxy_capture import ProxyCapture, _MITMPROXY_AVAILABLE
from hdwp.core.state_machine.learner import _obs_to_symbol
from hdwp.core.model.schemas import (
    NormalizedRequest, NormalizedResponse, ObservationType, RawObservation
)


def _make_context(base_url: str = "http://test.local") -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url=base_url, name="Test"),
        scope=ScopeConfig(include=[f"{base_url}/*"]),
        options=OptionsConfig(allow_write=False, max_requests_per_minute=600),
    )
    return EngineContext(config=config, base_url=base_url, session_id="test-session")


def test_proxy_capture_instantiates_without_mitmproxy():
    """ProxyCapture can be instantiated even if mitmproxy is not installed."""
    ctx = _make_context()
    bus = AsyncEventBus()
    scope_guard = ScopeGuard(ctx)
    capture = ProxyCapture(bus, scope_guard, "session-1", port=8888)
    assert capture.running is False
    assert capture.address == "127.0.0.1:8888"


@pytest.mark.asyncio
async def test_proxy_capture_start_raises_if_no_mitmproxy():
    """ProxyCapture.start() raises RuntimeError when mitmproxy is absent."""
    if _MITMPROXY_AVAILABLE:
        pytest.skip("mitmproxy is installed — skip absence test")
    ctx = _make_context()
    bus = AsyncEventBus()
    scope_guard = ScopeGuard(ctx)
    capture = ProxyCapture(bus, scope_guard, "session-1")
    with pytest.raises(RuntimeError, match="mitmproxy"):
        await capture.start()


def test_obs_to_symbol_200():
    """Observation with status 200 maps to 2xx bucket."""
    obs = RawObservation(
        timestamp="2026-01-01T00:00:00Z",
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url="http://test.local/api/users/1"),
        response=NormalizedResponse(status_code=200),
        session_id="s1",
    )
    path, method, bucket = _obs_to_symbol(obs)
    assert method == "GET"
    assert bucket == "2xx"
    assert "{id_0}" in path


def test_obs_to_symbol_401():
    """Observation with status 401 maps to auth_error bucket."""
    obs = RawObservation(
        timestamp="2026-01-01T00:00:00Z",
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url="http://test.local/api/login"),
        response=NormalizedResponse(status_code=401),
        session_id="s1",
    )
    _, _, bucket = _obs_to_symbol(obs)
    assert bucket == "auth_error"


def test_obs_to_symbol_no_response():
    """Observation without response/request returns default symbol."""
    obs = RawObservation(
        timestamp="2026-01-01T00:00:00Z",
        source="active",
        type=ObservationType.HTTP,
        session_id="s1",
    )
    sym = _obs_to_symbol(obs)
    assert sym == ("unknown", "GET", "0xx")
