# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.context.config_schema import (
    DiscoveryConfig,
    HDWPContextConfig,
    OptionsConfig,
    RoleConfig,
    ScopeConfig,
    TargetConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.observation.openapi_seeder import (
    _infer_response_body,
    _schema_to_example,
    seed_from_openapi,
)


def _make_context(
    openapi_spec: str | None = None,
    seed_endpoints: list[str] | None = None,
    roles: list[RoleConfig] | None = None,
) -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url="http://test.local", name="Test"),
        scope=ScopeConfig(include=["http://test.local/*"]),
        roles=roles or [
            RoleConfig(name="anonymous"),
            RoleConfig(name="user_a"),
        ],
        options=OptionsConfig(max_requests_per_minute=600),
        discovery=DiscoveryConfig(
            openapi_spec=openapi_spec,
            seed_endpoints=seed_endpoints or [],
        ),
    )
    return EngineContext(config=config, base_url="http://test.local", session_id="test")


SAMPLE_SPEC: dict = {
    "openapi": "3.0.0",
    "paths": {
        "/api/users": {"get": {"responses": {"200": {}}}},
        "/api/orders/{id}": {"get": {"responses": {"200": {}}}},
    },
}


@pytest.mark.asyncio
async def test_no_seeding_without_spec() -> None:
    context = _make_context()
    bus = AsyncEventBus()
    received = []
    bus.on(OBSERVATION_RAW, lambda e: received.append(e))
    count = await seed_from_openapi(bus, context)
    await bus.drain()
    assert count == 0
    assert received == []


@pytest.mark.asyncio
async def test_seed_emits_observations_from_spec() -> None:
    context = _make_context(openapi_spec="/fake/spec.json")
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)

    with patch(
        "hdwp.core.observation.openapi_seeder._load_spec",
        new_callable=AsyncMock,
        return_value=SAMPLE_SPEC,
    ):
        count = await seed_from_openapi(bus, context)

    await bus.drain()
    # 2 endpoints × 2 rôles = 4 observations
    assert count == 4
    assert len(received) == 4


@pytest.mark.asyncio
async def test_seed_endpoints_from_seed_list() -> None:
    context = _make_context(seed_endpoints=["/api/users", "/api/admin"])
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)
    count = await seed_from_openapi(bus, context)
    await bus.drain()
    # 2 endpoints × 2 rôles = 4 observations
    assert count == 4
    assert len(received) == 4


@pytest.mark.asyncio
async def test_load_json_spec(tmp_path) -> None:
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SAMPLE_SPEC))
    from hdwp.core.observation.openapi_seeder import _load_spec
    result = await _load_spec(str(spec_file))
    assert result is not None
    assert "paths" in result


@pytest.mark.asyncio
async def test_load_yaml_spec(tmp_path) -> None:
    import yaml
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(yaml.dump(SAMPLE_SPEC))
    from hdwp.core.observation.openapi_seeder import _load_spec
    result = await _load_spec(str(spec_file))
    assert result is not None
    assert "paths" in result


def test_infer_response_body_with_schema() -> None:
    operation = {
        "responses": {
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "string"},
                            },
                        }
                    }
                }
            }
        }
    }
    body = _infer_response_body(operation)
    assert body is not None
    assert body["id"] == 1
    assert body["name"] == "example"


def test_infer_response_body_no_schema() -> None:
    body = _infer_response_body({"responses": {"200": {}}})
    assert body is None


def test_schema_to_example_object() -> None:
    schema = {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "active": {"type": "boolean"},
        },
    }
    result = _schema_to_example(schema)
    assert result == {"count": 1, "active": True}


@pytest.mark.asyncio
async def test_load_spec_missing_file() -> None:
    from hdwp.core.observation.openapi_seeder import _load_spec
    result = await _load_spec("/nonexistent/path.json")
    assert result is None


@pytest.mark.asyncio
async def test_url_out_of_scope_filtered() -> None:
    """Les URLs hors-scope (dans exclude) ne doivent pas être émises."""
    from hdwp.core.context.config_schema import DiscoveryConfig
    config = HDWPContextConfig(
        target=TargetConfig(base_url="http://test.local", name="Test"),
        scope=ScopeConfig(
            include=["http://test.local/*"],
            exclude=["http://test.local/logout"],
        ),
        roles=[RoleConfig(name="anonymous")],
        options=OptionsConfig(max_requests_per_minute=600),
        discovery=DiscoveryConfig(seed_endpoints=["/api/users", "/logout"]),
    )
    ctx = EngineContext(config=config, base_url="http://test.local", session_id="test")
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)
    count = await seed_from_openapi(bus, ctx)
    await bus.drain()

    # /logout est exclu du scope → seulement /api/users émis (1 rôle × 1 endpoint = 1)
    assert count == 1
    urls = [e.payload["request"]["url"] for e in received]
    assert all("/logout" not in u for u in urls), f"URL hors-scope émise : {urls}"


@pytest.mark.asyncio
async def test_security_requirement_emits_401_for_anonymous() -> None:
    """Endpoint avec security requirement → observation 401 pour anonymous."""
    spec_with_security = {
        "openapi": "3.0.0",
        "paths": {
            "/api/admin": {
                "get": {
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {}},
                }
            }
        },
    }
    context = _make_context(openapi_spec="/fake/spec.json")
    bus = AsyncEventBus()
    received = []

    async def handler(e):
        received.append(e)

    bus.on(OBSERVATION_RAW, handler)
    with patch(
        "hdwp.core.observation.openapi_seeder._load_spec",
        new_callable=AsyncMock,
        return_value=spec_with_security,
    ):
        await seed_from_openapi(bus, context)

    await bus.drain()

    # Trouver l'observation pour anonymous
    anon_obs = [e for e in received if "anonymous" in str(e.payload.get("tags", []))]
    assert len(anon_obs) == 1
    assert anon_obs[0].payload["response"]["status_code"] == 401, (
        "anonymous devrait recevoir 401 sur endpoint sécurisé"
    )

    # user_a devrait recevoir 200
    auth_obs = [e for e in received if "user_a" in str(e.payload.get("tags", []))]
    assert len(auth_obs) == 1
    assert auth_obs[0].payload["response"]["status_code"] == 200
