# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for credential auto-capture via proxy."""
from __future__ import annotations

import pytest

from hdwp.core.observation.proxy_capture import _extract_auth_token


@pytest.fixture
def seen_tokens() -> set[str]:
    """Fixture providing a fresh seen_tokens set for each test."""
    return set()


def _clear_seen() -> None:
    """Legacy helper — deprecated."""
    pass


def test_extract_bearer_from_json_body(seen_tokens: set[str]) -> None:
    result = _extract_auth_token({"token": "abc123abc123abc"}, {}, seen_tokens)
    assert result == ("bearer", "abc123abc123abc")


def test_extract_access_token_from_json(seen_tokens: set[str]) -> None:
    result = _extract_auth_token({"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}, {}, seen_tokens)
    assert result is not None
    assert result[0] == "bearer"


def test_extract_session_cookie(seen_tokens: set[str]) -> None:
    result = _extract_auth_token(None, {"set-cookie": "session=xyz789xyz789xyz789; HttpOnly"}, seen_tokens)
    assert result == ("cookie", "xyz789xyz789xyz789")


def test_deduplication_returns_none_second_time(seen_tokens: set[str]) -> None:
    first = _extract_auth_token({"token": "unique_token_12345"}, {}, seen_tokens)
    assert first == ("bearer", "unique_token_12345")
    second = _extract_auth_token({"token": "unique_token_12345"}, {}, seen_tokens)
    assert second is None


def test_short_token_ignored(seen_tokens: set[str]) -> None:
    result = _extract_auth_token({"token": "short"}, {}, seen_tokens)
    assert result is None


def test_no_auth_fields_returns_none(seen_tokens: set[str]) -> None:
    result = _extract_auth_token({"user": "alice", "email": "a@b.com"}, {}, seen_tokens)
    assert result is None


def test_non_dict_body_falls_through_to_cookie(seen_tokens: set[str]) -> None:
    result = _extract_auth_token("plain text", {"set-cookie": "token=my_session_tok_xyz; Path=/"}, seen_tokens)
    assert result is not None
    assert result[0] == "cookie"


@pytest.mark.asyncio
async def test_session_manager_add_role() -> None:
    from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
    from hdwp.core.experiment.session_manager import SessionManager

    sm = SessionManager([])
    role = RoleConfig(
        name="captured_1",
        credentials=CredentialConfig(type="bearer", token="test_token_xyz"),
    )
    await sm.add_role(role)
    client = sm.get_client("captured_1")
    assert client is not None
    auth = sm.build_auth_headers("captured_1")
    assert "Authorization" in auth
    assert "test_token_xyz" in auth["Authorization"]
    await sm.close_all()


@pytest.mark.asyncio
async def test_session_manager_add_role_idempotent() -> None:
    from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
    from hdwp.core.experiment.session_manager import SessionManager

    sm = SessionManager([])
    role = RoleConfig(
        name="captured_1",
        credentials=CredentialConfig(type="bearer", token="tok"),
    )
    await sm.add_role(role)
    await sm.add_role(role)  # second call should be no-op
    assert len(sm._roles) == 1
    await sm.close_all()
