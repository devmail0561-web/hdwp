# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.observation.js_extractor import JSExtractor

BASE = "http://app.test"


@pytest.fixture
def extractor() -> JSExtractor:
    return JSExtractor()


def test_fetch_simple(extractor: JSExtractor) -> None:
    js = "fetch('/api/users')"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/users" in result


def test_fetch_template_literal(extractor: JSExtractor) -> None:
    js = "fetch(`/api/users/${id}`)"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/users/{{param}}" in result


def test_url_property(extractor: JSExtractor) -> None:
    js = "url: '/api/orders'"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/orders" in result


def test_standalone_string(extractor: JSExtractor) -> None:
    js = '"/api/v1/products"'
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/v1/products" in result


def test_js_extension_filtered(extractor: JSExtractor) -> None:
    js = '"/api/bundle.js"'
    result = extractor.extract_endpoints(js, BASE)
    assert not any(".js" in r for r in result)


def test_too_many_segments_filtered(extractor: JSExtractor) -> None:
    js = '"/api/a/b/c/d/e/f/g/h"'
    result = extractor.extract_endpoints(js, BASE)
    assert not any("a/b/c/d/e/f/g/h" in r for r in result)


def test_deduplication(extractor: JSExtractor) -> None:
    js = "fetch('/api/users')\naxios.get('/api/users')"
    result = extractor.extract_endpoints(js, BASE)
    assert result.count(f"{BASE}/api/users") == 1


def test_empty_source(extractor: JSExtractor) -> None:
    result = extractor.extract_endpoints("", BASE)
    assert result == []


def test_base_url_prefix(extractor: JSExtractor) -> None:
    js = '"/api/items"'
    result = extractor.extract_endpoints(js, "https://secure.example.com")
    assert "https://secure.example.com/api/items" in result
