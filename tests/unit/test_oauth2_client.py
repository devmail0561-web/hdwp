# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.context.config_schema import CredentialConfig
from hdwp.core.experiment.oauth2_client import OAuth2Client, OAuth2Error


def _make_cred(type_: str, **kwargs) -> CredentialConfig:
    return CredentialConfig(
        type=type_,
        token_endpoint="https://auth.test/token",
        client_id="test_client",
        client_secret="test_secret",
        **kwargs,
    )


def _mock_token_response(token: str = "access_tok", expires_in: int = 3600) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"access_token": token, "expires_in": expires_in}
    return mock_resp


@pytest.mark.asyncio
async def test_get_token_acquires_on_first_call() -> None:
    cred = _make_cred("oauth2_password", username="u", password="p")
    client = OAuth2Client(cred)
    mock_resp = _mock_token_response("tok_abc")

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        token = await client.get_token()

    assert token == "tok_abc"
    mock_http.post.assert_called_once()


@pytest.mark.asyncio
async def test_get_token_caches_within_window() -> None:
    cred = _make_cred("oauth2_password", username="u", password="p")
    client = OAuth2Client(cred)
    mock_resp = _mock_token_response("tok_cached", expires_in=3600)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        t1 = await client.get_token()
        t2 = await client.get_token()

    assert t1 == t2 == "tok_cached"
    # Called only once (cache hit on second call)
    assert mock_http.post.call_count == 1


@pytest.mark.asyncio
async def test_force_refresh_ignores_cache() -> None:
    cred = _make_cred("oauth2_client_credentials")
    client = OAuth2Client(cred)
    mock_resp = _mock_token_response("new_tok", expires_in=3600)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        # Set a "fresh" token manually
        client._access_token = "old_tok"
        client._expires_at = time.monotonic() + 3000

        t = await client.force_refresh()

    assert t == "new_tok"
    assert mock_http.post.call_count == 1


@pytest.mark.asyncio
async def test_client_credentials_grant_type() -> None:
    cred = _make_cred("oauth2_client_credentials")
    client = OAuth2Client(cred)
    mock_resp = _mock_token_response()
    captured_data: list = []

    async def _fake_post(url, data=None, **kwargs):
        captured_data.append(data)
        return mock_resp

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=_fake_post)
        mock_cls.return_value = mock_http

        await client.get_token()

    assert captured_data[0]["grant_type"] == "client_credentials"


@pytest.mark.asyncio
async def test_password_grant_type() -> None:
    cred = _make_cred("oauth2_password", username="alice", password="secret")
    client = OAuth2Client(cred)
    mock_resp = _mock_token_response()
    captured_data: list = []

    async def _fake_post(url, data=None, **kwargs):
        captured_data.append(data)
        return mock_resp

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=_fake_post)
        mock_cls.return_value = mock_http

        await client.get_token()

    assert captured_data[0]["grant_type"] == "password"
    assert captured_data[0]["username"] == "alice"


@pytest.mark.asyncio
async def test_missing_token_endpoint_raises() -> None:
    cred = CredentialConfig(type="oauth2_password")
    client = OAuth2Client(cred)
    with pytest.raises(OAuth2Error, match="token_endpoint"):
        await client.get_token()
