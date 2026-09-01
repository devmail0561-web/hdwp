# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
from hdwp.core.experiment.session_manager import SessionManager


def _bearer_role(name: str, token: str) -> RoleConfig:
    return RoleConfig(name=name, credentials=CredentialConfig(type="bearer", token=token))


def _oauth2_role(name: str) -> RoleConfig:
    return RoleConfig(
        name=name,
        credentials=CredentialConfig(
            type="oauth2_client_credentials",
            token_endpoint="https://auth.test/token",
            client_id="cid",
            client_secret="csecret",
        ),
    )


@pytest.mark.asyncio
async def test_resolve_auth_headers_bearer() -> None:
    """Rôle bearer → retourne headers sync via build_auth_headers."""
    sm = SessionManager([_bearer_role("user_a", "my_token")])
    headers = await sm.resolve_auth_headers("user_a")
    assert headers == {"Authorization": "Bearer my_token"}


@pytest.mark.asyncio
async def test_resolve_auth_headers_oauth2() -> None:
    """Rôle OAuth2 → appelle get_token() sur le client OAuth2."""
    role = _oauth2_role("svc")
    sm = SessionManager([role])

    # Mock le client OAuth2
    mock_oauth = AsyncMock()
    mock_oauth.get_token = AsyncMock(return_value="oauth_tok_xyz")
    sm._oauth_clients["svc"] = mock_oauth

    headers = await sm.resolve_auth_headers("svc")
    assert headers == {"Authorization": "Bearer oauth_tok_xyz"}
    mock_oauth.get_token.assert_called_once()


@pytest.mark.asyncio
async def test_resolve_auth_headers_unknown_role() -> None:
    """Rôle inconnu → retourne dict vide, pas de crash."""
    sm = SessionManager([])
    headers = await sm.resolve_auth_headers("nonexistent")
    assert headers == {}


@pytest.mark.asyncio
async def test_resolve_auth_headers_oauth2_failure() -> None:
    """Erreur OAuth2 → retourne dict vide (log warning, pas de crash)."""
    from hdwp.core.experiment.oauth2_client import OAuth2Error

    role = _oauth2_role("svc")
    sm = SessionManager([role])
    mock_oauth = AsyncMock()
    mock_oauth.get_token = AsyncMock(side_effect=OAuth2Error("network error"))
    sm._oauth_clients["svc"] = mock_oauth

    headers = await sm.resolve_auth_headers("svc")
    assert headers == {}


@pytest.mark.asyncio
async def test_add_role_creates_oauth2_client() -> None:
    """add_role pour un rôle OAuth2 crée automatiquement un OAuth2Client."""
    sm = SessionManager([])
    oauth2_role = _oauth2_role("new_svc")
    await sm.add_role(oauth2_role)

    assert "new_svc" in sm._roles
    assert "new_svc" in sm._oauth_clients
    from hdwp.core.experiment.oauth2_client import OAuth2Client
    assert isinstance(sm._oauth_clients["new_svc"], OAuth2Client)
