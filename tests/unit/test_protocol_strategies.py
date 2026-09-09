# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for the 4 protocol bypass strategies."""

from __future__ import annotations

import base64

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.strategies.protocol import PROTOCOL_STRATEGIES


def _get(name: str):
    for s in PROTOCOL_STRATEGIES:
        if s.name == name:
            return s
    raise KeyError(f"Strategy {name!r} not found")


def _req(
    url: str = "http://target/api",
    method: str = "GET",
    headers: dict | None = None,
    body: object = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        url=url,
        headers=headers or {"Content-Type": "application/json"},
        body=body,
        query_params={},
        path_params={},
    )


# ── http2_smuggling ───────────────────────────────────────────────────────

class TestHttp2Smuggling:
    s = _get("http2_smuggling")

    def test_injects_method_pseudo_header(self):
        req = _req(method="POST")
        result = self.s.apply(req, {})
        assert result.request.headers[":method"] == "POST"

    def test_injects_path_pseudo_header(self):
        req = _req(url="http://target/api/users?id=1")
        result = self.s.apply(req, {})
        assert result.request.headers[":path"].startswith("/api/users")

    def test_injects_scheme_pseudo_header(self):
        req = _req(url="https://target/api")
        result = self.s.apply(req, {})
        assert result.request.headers[":scheme"] == "https"

    def test_injects_authority_pseudo_header(self):
        req = _req(url="http://target/api")
        result = self.s.apply(req, {})
        assert result.request.headers[":authority"] == "target"

    def test_adds_transfer_encoding_chunked(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["Transfer-Encoding"] == "chunked"

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── websocket_upgrade ─────────────────────────────────────────────────────

class TestWebsocketUpgrade:
    s = _get("websocket_upgrade")

    def test_adds_upgrade_header(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["Upgrade"] == "websocket"

    def test_adds_connection_upgrade(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["Connection"] == "Upgrade"

    def test_adds_sec_websocket_version(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["Sec-WebSocket-Version"] == "13"

    def test_ws_key_is_valid_base64(self):
        result = self.s.apply(_req(), {})
        key = result.request.headers["Sec-WebSocket-Key"]
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

    def test_ws_keys_differ_between_calls(self):
        keys = {self.s.apply(_req(), {}).request.headers["Sec-WebSocket-Key"]
                for _ in range(10)}
        assert len(keys) > 1

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── ipv6_bypass ───────────────────────────────────────────────────────────

class TestIpv6Bypass:
    s = _get("ipv6_bypass")

    def test_loopback_converts_127_0_0_1(self):
        req = _req(url="http://127.0.0.1/api")
        result = self.s.apply(req, {})
        assert "[::1]" in result.request.url

    def test_loopback_converts_localhost(self):
        req = _req(url="http://localhost/api")
        result = self.s.apply(req, {})
        assert "[::1]" in result.request.url

    def test_mapped_mode_converts_ipv4(self):
        req = _req(url="http://1.2.3.4/api")
        result = self.s.apply(req, {"mode": "mapped"})
        assert "::ffff:" in result.request.url

    def test_no_match_returns_request_unchanged(self):
        req = _req(url="http://example.com/api")
        result = self.s.apply(req, {})
        assert result.request.url == req.url

    def test_path_preserved_after_conversion(self):
        req = _req(url="http://127.0.0.1/api/resource?x=1")
        result = self.s.apply(req, {})
        assert "/api/resource" in result.request.url

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── tls_fingerprint ───────────────────────────────────────────────────────

class TestTlsFingerprint:
    s = _get("tls_fingerprint")

    def test_chrome_sets_user_agent(self):
        result = self.s.apply(_req(), {})
        ua = result.request.headers["User-Agent"]
        assert "Mozilla/5.0" in ua
        assert "Chrome/124" in ua

    def test_firefox_profile(self):
        result = self.s.apply(_req(), {"profile": "firefox_latest"})
        ua = result.request.headers["User-Agent"]
        assert "Firefox/125" in ua

    def test_safari_profile(self):
        result = self.s.apply(_req(), {"profile": "safari_latest"})
        ua = result.request.headers["User-Agent"]
        assert "Safari" in ua

    def test_unknown_profile_falls_back_to_chrome(self):
        result = self.s.apply(_req(), {"profile": "nonexistent"})
        ua = result.request.headers["User-Agent"]
        assert "Chrome" in ua

    def test_original_headers_preserved(self):
        req = _req(headers={"Authorization": "Bearer token123"})
        result = self.s.apply(req, {})
        assert result.request.headers.get("Authorization") == "Bearer token123"

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── All strategies have required fields ───────────────────────────────────

def test_all_protocol_strategies_have_required_fields():
    for s in PROTOCOL_STRATEGIES:
        assert s.name
        assert s.category == "protocol"
        assert callable(s.apply)
        assert s.description
        assert s.risk_level in ("low", "medium", "high")
