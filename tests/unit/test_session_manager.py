# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest
import httpx

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
from hdwp.core.experiment.session_manager import SessionManager, TokenExpiredError


def _make_roles() -> list[RoleConfig]:
    return [
        RoleConfig(name="anonymous"),
        RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="tok_a")),
        RoleConfig(name="user_b", credentials=CredentialConfig(type="basic", username="bob", password="pass")),
        RoleConfig(name="api_user", credentials=CredentialConfig(type="api_key", token="key123")),
        RoleConfig(name="cookie_user", credentials=CredentialConfig(type="cookie", token="sess=abc")),
    ]


def test_build_auth_headers_bearer():
    sm = SessionManager(_make_roles())
    headers = sm.build_auth_headers("user_a")
    assert headers == {"Authorization": "Bearer tok_a"}


def test_build_auth_headers_basic():
    import base64
    sm = SessionManager(_make_roles())
    headers = sm.build_auth_headers("user_b")
    expected = base64.b64encode(b"bob:pass").decode()
    assert headers == {"Authorization": f"Basic {expected}"}


def test_build_auth_headers_api_key():
    sm = SessionManager(_make_roles())
    headers = sm.build_auth_headers("api_user")
    assert headers == {"X-Api-Key": "key123"}


def test_build_auth_headers_cookie():
    sm = SessionManager(_make_roles())
    headers = sm.build_auth_headers("cookie_user")
    assert headers == {"Cookie": "sess=abc"}


def test_build_auth_headers_null_credentials():
    sm = SessionManager(_make_roles())
    assert sm.build_auth_headers("anonymous") == {}


def test_build_auth_headers_unknown_role():
    sm = SessionManager(_make_roles())
    assert sm.build_auth_headers("ghost") == {}


def test_update_csrf_from_header():
    sm = SessionManager(_make_roles())
    resp = httpx.Response(200, headers={"X-CSRF-Token": "csrf_val_123"})
    sm.update_csrf(resp, "user_a")
    assert sm._csrf_tokens["user_a"] == "csrf_val_123"


def test_update_csrf_from_cookie():
    sm = SessionManager(_make_roles())
    resp = httpx.Response(200, headers={"Set-Cookie": "csrf_token=cookie_csrf; Path=/"})
    sm.update_csrf(resp, "user_a")
    assert sm._csrf_tokens["user_a"] == "cookie_csrf"


def test_update_csrf_no_token():
    sm = SessionManager(_make_roles())
    resp = httpx.Response(200)
    sm.update_csrf(resp, "user_a")
    assert "user_a" not in sm._csrf_tokens


def test_inject_csrf_adds_header():
    sm = SessionManager(_make_roles())
    sm._csrf_tokens["user_a"] = "my_csrf"
    headers = sm.inject_csrf({"Accept": "application/json"}, "user_a")
    assert headers["X-CSRF-Token"] == "my_csrf"
    assert headers["Accept"] == "application/json"


def test_inject_csrf_does_not_mutate_input():
    sm = SessionManager(_make_roles())
    sm._csrf_tokens["user_a"] = "my_csrf"
    original = {"Accept": "application/json"}
    sm.inject_csrf(original, "user_a")
    assert "X-CSRF-Token" not in original


def test_inject_csrf_no_token_returns_unchanged():
    sm = SessionManager(_make_roles())
    headers = {"Accept": "application/json"}
    result = sm.inject_csrf(headers, "user_a")
    assert result == headers


def test_check_token_expired_raises_on_401():
    sm = SessionManager(_make_roles())
    resp = httpx.Response(401)
    with pytest.raises(TokenExpiredError) as exc_info:
        sm.check_token_expired(resp, "user_a")
    assert exc_info.value.role_name == "user_a"


def test_check_token_expired_ok_on_200():
    sm = SessionManager(_make_roles())
    resp = httpx.Response(200)
    sm.check_token_expired(resp, "user_a")  # should not raise


def test_prepare_headers_combines_auth_and_csrf():
    sm = SessionManager(_make_roles())
    sm._csrf_tokens["user_a"] = "csrf_tok"
    result = sm.prepare_headers("user_a", {"X-Custom": "val"})
    assert result["Authorization"] == "Bearer tok_a"
    assert result["X-CSRF-Token"] == "csrf_tok"
    assert result["X-Custom"] == "val"


@pytest.mark.asyncio
async def test_context_manager_creates_and_closes_clients():
    roles = [RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="tok"))]
    async with SessionManager(roles) as sm:
        client = sm.get_client("user_a")
        assert isinstance(client, httpx.AsyncClient)
    assert len(sm._clients) == 0
