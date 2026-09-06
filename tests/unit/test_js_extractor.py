# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.observation.js_extractor import JSExtractor

BASE = "http://app.test"


@pytest.fixture
def extractor() -> JSExtractor:
    return JSExtractor()


def _urls(result: list[tuple[str, str]]) -> list[str]:
    """Extract URLs from (url, method) tuples."""
    return [url for url, _method in result]


def test_fetch_simple(extractor: JSExtractor) -> None:
    js = "fetch('/api/users')"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/users" in _urls(result)


def test_fetch_template_literal(extractor: JSExtractor) -> None:
    js = "fetch(`/api/users/${id}`)"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/users/{{param}}" in _urls(result)


def test_url_property(extractor: JSExtractor) -> None:
    js = "url: '/api/orders'"
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/orders" in _urls(result)


def test_standalone_string(extractor: JSExtractor) -> None:
    js = '"/api/v1/products"'
    result = extractor.extract_endpoints(js, BASE)
    assert f"{BASE}/api/v1/products" in _urls(result)


def test_js_extension_filtered(extractor: JSExtractor) -> None:
    js = '"/api/bundle.js"'
    result = extractor.extract_endpoints(js, BASE)
    assert not any(".js" in url for url, _m in result)


def test_too_many_segments_filtered(extractor: JSExtractor) -> None:
    js = '"/api/a/b/c/d/e/f/g/h"'
    result = extractor.extract_endpoints(js, BASE)
    assert not any("a/b/c/d/e/f/g/h" in url for url, _m in result)


def test_deduplication(extractor: JSExtractor) -> None:
    js = "fetch('/api/users')\naxios.get('/api/users')"
    result = extractor.extract_endpoints(js, BASE)
    assert _urls(result).count(f"{BASE}/api/users") == 1


def test_empty_source(extractor: JSExtractor) -> None:
    result = extractor.extract_endpoints("", BASE)
    assert result == []


def test_base_url_prefix(extractor: JSExtractor) -> None:
    js = '"/api/items"'
    result = extractor.extract_endpoints(js, "https://secure.example.com")
    assert "https://secure.example.com/api/items" in _urls(result)


def test_axios_method_captured(extractor: JSExtractor) -> None:
    """axios.post() should capture method POST, not default to GET."""
    js = "axios.post('/api/users', data)"
    result = extractor.extract_endpoints(js, BASE)
    methods = {method for url, method in result if url == f"{BASE}/api/users"}
    assert "POST" in methods
