# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for BypassRegistry — singleton, registration, WAF lookup, detection."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import yaml

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.bypass_registry import (
    BypassRegistry,
    BypassResult,
    BypassStrategy,
    get_bypass_registry,
)


@pytest.fixture(autouse=True)
def reset_registry():
    BypassRegistry.reset_for_testing()
    yield
    BypassRegistry.reset_for_testing()


def _req(
    url: str = "http://target/api/users/1",
    method: str = "GET",
    headers: dict | None = None,
    body: object = None,
    query_params: dict | None = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        url=url,
        headers=headers or {},
        body=body,
        query_params=query_params or {},
        path_params={},
    )


def _dummy_strategy(name: str = "dummy") -> BypassStrategy:
    return BypassStrategy(
        name=name,
        category="evasion",
        apply=lambda req, params: BypassResult(request=req),
        description="test strategy",
    )


# ── Singleton ─────────────────────────────────────────────────────────────

class TestSingleton:
    def test_same_instance(self):
        a = BypassRegistry()
        b = BypassRegistry()
        assert a is b

    def test_reset_clears_instance(self):
        a = BypassRegistry()
        BypassRegistry.reset_for_testing()
        b = BypassRegistry()
        assert a is not b

    def test_thread_safe_creation(self):
        instances = []
        def create():
            instances.append(BypassRegistry())
        threads = [threading.Thread(target=create) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len({id(i) for i in instances}) == 1


# ── Registration ──────────────────────────────────────────────────────────

class TestRegister:
    def test_register_adds_strategy(self):
        r = BypassRegistry()
        initial_count = len(r.list_strategies())
        r.register(_dummy_strategy("new_one"))
        assert "new_one" in r.list_strategies()
        assert len(r.list_strategies()) == initial_count + 1

    def test_register_duplicate_is_noop(self):
        r = BypassRegistry()
        r.register(_dummy_strategy("dup"))
        count_after_first = len(r.list_strategies())
        r.register(_dummy_strategy("dup"))
        assert len(r.list_strategies()) == count_after_first

    def test_get_by_name_returns_strategy(self):
        r = BypassRegistry()
        s = _dummy_strategy("findme")
        r.register(s)
        assert r.get_by_name("findme") is s

    def test_get_by_name_unknown_returns_none(self):
        r = BypassRegistry()
        assert r.get_by_name("nonexistent") is None


# ── Built-ins loaded ──────────────────────────────────────────────────────

class TestBuiltins:
    def test_fifteen_strategies_loaded(self):
        r = BypassRegistry()
        assert len(r.list_strategies()) == 15

    def test_all_expected_names_present(self):
        r = BypassRegistry()
        expected = {
            "whitespace_variation", "junk_char", "cl_te_smuggling", "te_cl_smuggling",
            "hpp", "multipart_boundary", "chunked_abuse", "content_type_confusion",
            "slowloris", "rate_limit_evasion", "cache_poisoning",
            "http2_smuggling", "websocket_upgrade", "ipv6_bypass", "tls_fingerprint",
        }
        assert expected <= set(r.list_strategies())


# ── WAF lookup ────────────────────────────────────────────────────────────

class TestGetStrategiesForWaf:
    def test_cloudflare_returns_hpp_first(self):
        r = BypassRegistry()
        strategies = r.get_strategies_for_waf("waf:cloudflare", max_count=3)
        assert len(strategies) > 0
        assert strategies[0].name == "hpp"

    def test_waf_prefix_normalized(self):
        r = BypassRegistry()
        with_prefix = [s.name for s in r.get_strategies_for_waf("waf:cloudflare")]
        without_prefix = [s.name for s in r.get_strategies_for_waf("cloudflare")]
        assert with_prefix == without_prefix

    def test_unknown_waf_falls_back_to_generic(self):
        r = BypassRegistry()
        strategies = r.get_strategies_for_waf("waf:nonexistent", max_count=3)
        names = [s.name for s in strategies]
        assert "whitespace_variation" in names

    def test_max_count_respected(self):
        r = BypassRegistry()
        strategies = r.get_strategies_for_waf("waf:cloudflare", max_count=2)
        assert len(strategies) <= 2

    def test_filter_by_category_evasion(self):
        r = BypassRegistry()
        strategies = r.get_strategies_for_waf("waf:cloudflare", max_count=5, category="evasion")
        assert all(s.category == "evasion" for s in strategies)

    def test_filter_by_category_timing(self):
        r = BypassRegistry()
        strategies = r.get_strategies_for_waf("waf:cloudflare", max_count=5, category="timing")
        assert all(s.category == "timing" for s in strategies)

    def test_empty_for_unknown_waf_and_no_generic(self):
        r = BypassRegistry()
        # Clear all WAF indices to simulate a registry with no signatures
        r._waf_index.clear()
        r._waf_signatures.clear()
        strategies = r.get_strategies_for_waf("waf:nonexistent_really", max_count=3)
        assert strategies == []


# ── apply_bypass ──────────────────────────────────────────────────────────

class TestApplyBypass:
    def test_known_strategy_applied(self):
        r = BypassRegistry()
        req = _req(headers={"Content-Type": "application/json"})
        result = r.apply_bypass("whitespace_variation", req)
        assert isinstance(result, BypassResult)
        assert result.strategy_name == "whitespace_variation"

    def test_unknown_strategy_returns_original(self):
        r = BypassRegistry()
        req = _req()
        result = r.apply_bypass("nonexistent_strategy", req)
        assert result.request is req
        assert result.raw_override is None

    def test_exception_in_apply_returns_original(self):
        r = BypassRegistry()
        def bad_apply(req, params):
            raise RuntimeError("boom")
        r.register(BypassStrategy(
            name="bad_strategy",
            category="evasion",
            apply=bad_apply,
            description="raises",
        ))
        req = _req()
        result = r.apply_bypass("bad_strategy", req)
        assert result.request is req


# ── detect_waf_from_response ──────────────────────────────────────────────

class TestDetectWafFromResponse:
    def test_cloudflare_detected_by_header(self):
        r = BypassRegistry()
        result = r.detect_waf_from_response(
            headers={"cf-ray": "abc123-CDG"},
            status_code=403,
        )
        assert result == "waf:cloudflare"

    def test_modsecurity_detected_by_body(self):
        r = BypassRegistry()
        result = r.detect_waf_from_response(
            headers={},
            body="ModSecurity blocked this request",
            status_code=403,
        )
        assert result == "waf:modsecurity"

    def test_unknown_returns_none(self):
        r = BypassRegistry()
        result = r.detect_waf_from_response(
            headers={"x-custom": "nothing"},
            body="normal 403",
            status_code=403,
        )
        assert result is None

    def test_generic_detected_by_body_keyword(self):
        r = BypassRegistry()
        result = r.detect_waf_from_response(
            headers={},
            body="access denied by web application firewall",
            status_code=403,
        )
        assert result == "waf:generic"


# ── YAML loading ──────────────────────────────────────────────────────────

class TestWafSignaturesLoading:
    def test_missing_yaml_is_graceful(self, tmp_path):
        r = BypassRegistry()
        r._load_waf_signatures(yaml_path=tmp_path / "nonexistent.yaml")
        # Should not raise

    def test_malformed_yaml_is_graceful(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml: {{{", encoding="utf-8")
        r = BypassRegistry()
        r._load_waf_signatures(yaml_path=bad)
        # Should not raise

    def test_partial_yaml_loads_valid_entries(self, tmp_path):
        partial = tmp_path / "partial.yaml"
        partial.write_text(
            "good_waf:\n  headers: [x-good]\n  effective_bypasses: [whitespace_variation]\n"
            "bad_waf: not_a_dict\n",
            encoding="utf-8",
        )
        r = BypassRegistry()
        r._load_waf_signatures(yaml_path=partial)
        assert "good_waf" in r.list_waf_signatures()


# ── get_bypass_registry ───────────────────────────────────────────────────

def test_get_bypass_registry_returns_same_instance():
    a = get_bypass_registry()
    b = get_bypass_registry()
    assert a is b
