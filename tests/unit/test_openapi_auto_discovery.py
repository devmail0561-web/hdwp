# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json

import pytest
import respx
import httpx

from hdwp.core.observation.openapi_seeder import auto_discover_spec, _parse_spec_content

SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/api/users": {"get": {}},
        "/api/orders": {"post": {}},
    },
}


@pytest.mark.asyncio
async def test_auto_discover_finds_swagger_json() -> None:
    with respx.mock:
        respx.get("http://target.test/swagger.json").mock(
            return_value=httpx.Response(
                200,
                content=json.dumps(SAMPLE_SPEC).encode(),
                headers={"content-type": "application/json"},
            )
        )
        spec = await auto_discover_spec("http://target.test")
    assert spec is not None
    assert "paths" in spec
    assert "/api/users" in spec["paths"]


@pytest.mark.asyncio
async def test_auto_discover_returns_none_when_not_found() -> None:
    with respx.mock:
        # All discovery paths return 404
        respx.get(url__regex=r"http://notfound\.test/.*").mock(
            return_value=httpx.Response(404, content=b"Not Found")
        )
        spec = await auto_discover_spec("http://notfound.test")
    assert spec is None


def test_parse_spec_content_json() -> None:
    content = json.dumps({"openapi": "3.0.0", "paths": {}})
    result = _parse_spec_content(content)
    assert result is not None
    assert result["openapi"] == "3.0.0"


def test_parse_spec_content_invalid() -> None:
    result = _parse_spec_content("this is not json or yaml: : : :")
    # YAML may parse this as a string — check it's not a dict with openapi/paths
    if isinstance(result, dict):
        assert "openapi" not in result and "paths" not in result
    else:
        assert result is None or not isinstance(result, dict)


def test_parse_spec_content_empty() -> None:
    result = _parse_spec_content("")
    assert result is None or result == {} or result is None
