# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for the 3 timing bypass strategies."""

from __future__ import annotations

import ipaddress

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.strategies.timing import TIMING_STRATEGIES


def _get(name: str):
    for s in TIMING_STRATEGIES:
        if s.name == name:
            return s
    raise KeyError(f"Strategy {name!r} not found")


def _req(
    url: str = "http://target/api",
    body: object = None,
    headers: dict | None = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method="POST",
        url=url,
        headers=headers or {"Content-Type": "application/json"},
        body=body,
        query_params={},
        path_params={},
    )


# ── slowloris ─────────────────────────────────────────────────────────────

class TestSlowloris:
    s = _get("slowloris")

    def test_sets_large_content_length(self):
        result = self.s.apply(_req(body="payload"), {})
        assert result.request.headers["Content-Length"] == "1000000"

    def test_custom_fake_content_length(self):
        result = self.s.apply(_req(body="x"), {"fake_content_length": 500_000})
        assert result.request.headers["Content-Length"] == "500000"

    def test_sets_raw_override(self):
        result = self.s.apply(_req(body="payload"), {})
        assert result.raw_override is not None

    def test_raw_override_contains_body_bytes(self):
        result = self.s.apply(_req(body="hello"), {})
        assert result.raw_override == b"hello"

    def test_requires_special_execution_flag(self):
        assert self.s.requires_special_execution is True


# ── rate_limit_evasion ────────────────────────────────────────────────────

class TestRateLimitEvasion:
    s = _get("rate_limit_evasion")

    def test_adds_all_ip_headers(self):
        result = self.s.apply(_req(), {})
        headers = result.request.headers
        assert "X-Forwarded-For" in headers
        assert "X-Real-IP" in headers
        assert "X-Originating-IP" in headers
        assert "X-Remote-IP" in headers
        assert "X-Remote-Addr" in headers

    def test_ip_is_valid_ipv4(self):
        result = self.s.apply(_req(), {})
        xff = result.request.headers["X-Forwarded-For"]
        fake_ip = xff.split(",")[0].strip()
        ipaddress.IPv4Address(fake_ip)  # raises if invalid

    def test_ip_octets_in_range_1_254(self):
        for _ in range(10):
            result = self.s.apply(_req(), {})
            xff = result.request.headers["X-Forwarded-For"]
            fake_ip = xff.split(",")[0].strip()
            for octet in fake_ip.split("."):
                assert 1 <= int(octet) <= 254

    def test_different_calls_give_different_ips(self):
        ips = set()
        for _ in range(20):
            result = self.s.apply(_req(), {})
            ips.add(result.request.headers["X-Real-IP"])
        assert len(ips) > 1

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── cache_poisoning ───────────────────────────────────────────────────────

class TestCachePoisoning:
    s = _get("cache_poisoning")

    def test_adds_x_forwarded_host(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["X-Forwarded-Host"] == "hdwp-bypass.invalid"

    def test_custom_poison_host(self):
        result = self.s.apply(_req(), {"poison_host": "attacker.example.com"})
        assert result.request.headers["X-Forwarded-Host"] == "attacker.example.com"
        assert result.request.headers["X-Host"] == "attacker.example.com"

    def test_adds_x_original_url(self):
        req = _req(url="http://target/api/resource")
        result = self.s.apply(req, {})
        assert result.request.headers["X-Original-URL"] == "http://target/api/resource"

    def test_adds_cache_control_no_transform(self):
        result = self.s.apply(_req(), {})
        assert result.request.headers["Cache-Control"] == "no-transform"

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── All strategies have required fields ───────────────────────────────────

def test_all_timing_strategies_have_required_fields():
    for s in TIMING_STRATEGIES:
        assert s.name
        assert s.category == "timing"
        assert callable(s.apply)
        assert s.description
        assert s.risk_level in ("low", "medium", "high")
