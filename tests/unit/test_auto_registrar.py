# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.context.config_schema import (
    CredentialConfig,
    HDWPContextConfig,
    OptionsConfig,
    RoleConfig,
    ScopeConfig,
    TargetConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard, ScopeVerdict
from hdwp.core.observation.auto_registrar import AutoRegistrar


def _make_context(allow_write: bool = True) -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url="http://target.test", name="Test"),
        scope=ScopeConfig(include=["http://target.test/*"]),
        options=OptionsConfig(allow_write=allow_write, max_requests_per_minute=600),
    )
    return EngineContext(config=config, base_url="http://target.test", session_id="TEST-01")


def _make_registrar(allow_write: bool = True) -> AutoRegistrar:
    ctx = _make_context(allow_write)
    sg = ScopeGuard(ctx)
    sm = MagicMock()
    return AutoRegistrar(session_manager=sm, scope_guard=sg, context=ctx)


@pytest.mark.asyncio
async def test_register_returns_role_with_token() -> None:
    """Registration réussie avec token dans la réponse → RoleConfig créé."""
    registrar = _make_registrar()

    async def _fake_post(url, json=None, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"id": 42, "token": "abc123token"}
        return mock_resp

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=_fake_post)
        mock_cls.return_value = mock_http

        roles = await registrar.try_register_test_accounts()

    assert len(roles) >= 1
    assert roles[0].credentials is not None
    assert roles[0].credentials.type == "bearer"
    assert roles[0].credentials.token == "abc123token"
    assert "auto_test" in roles[0].name


@pytest.mark.asyncio
async def test_register_returns_empty_on_400() -> None:
    """Toutes les tentatives retournent 400 → liste vide, pas de crash."""
    registrar = _make_registrar()

    async def _fake_post(url, json=None, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        return mock_resp

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=_fake_post)
        mock_cls.return_value = mock_http

        roles = await registrar.try_register_test_accounts()

    assert roles == []


@pytest.mark.asyncio
async def test_cleanup_calls_delete() -> None:
    """cleanup() tente DELETE sur les IDs enregistrés."""
    registrar = _make_registrar()
    registrar._registered_ids = [42]
    deleted_urls: list[str] = []

    async def _fake_delete(url, **kwargs):
        deleted_urls.append(url)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        return mock_resp

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.delete = AsyncMock(side_effect=_fake_delete)
        mock_cls.return_value = mock_http

        await registrar.cleanup()

    assert any("42" in url for url in deleted_urls)


@pytest.mark.asyncio
async def test_no_registration_without_allow_write() -> None:
    """Sans allow_write, les endpoints POST ne sont pas tentés (ScopeGuard bloque)."""
    # Sans allow_write=True, les POST sont bloqués par ScopeGuard
    ctx = _make_context(allow_write=False)
    sg = ScopeGuard(ctx)
    sm = MagicMock()
    registrar = AutoRegistrar(session_manager=sm, scope_guard=sg, context=ctx)

    # Le ScopeGuard bloque les POST destructifs → try_register_test_accounts retourne []
    # car check(url, "POST") → BLOCKED_DESTRUCTIVE
    with patch("httpx.AsyncClient"):
        roles = await registrar.try_register_test_accounts()

    assert roles == []
