# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SessionManager: maintains per-role persistent HTTP sessions.

Responsibilities:
- Keep one httpx.AsyncClient per role (cookie jar persistence, connection reuse)
- Build Authorization / Cookie headers from RoleConfig credentials
- Extract and inject CSRF tokens from previous responses
- Detect token expiry (401 response) and signal it
"""
from __future__ import annotations

import asyncio
import base64
import re
from typing import Any, Self

import httpx
import structlog

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig

log = structlog.get_logger()

CSRF_HEADER_NAMES = frozenset({
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
})

CSRF_COOKIE_NAMES = frozenset({
    "csrf_token", "xsrf-token", "csrftoken", "_csrf",
})


class TokenExpiredError(Exception):
    """Raised when a role's token has expired (401 received)."""

    def __init__(self, role_name: str) -> None:
        super().__init__(f"Token expired for role '{role_name}'")
        self.role_name = role_name


class SessionManager:
    """
    Manages per-role HTTP sessions with auth header injection and CSRF tracking.

    Usage::

        async with SessionManager(roles) as sm:
            client = sm.get_client("user_a")
            resp = await client.get(url, headers=sm.build_auth_headers("user_a"))
            sm.update_csrf(resp, "user_a")
            sm.check_token_expired(resp, "user_a")
    """

    def __init__(self, roles: list[RoleConfig], proxy_url: str | None = None) -> None:
        self._roles: dict[str, RoleConfig] = {r.name: r for r in roles}
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._csrf_tokens: dict[str, str] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._proxy_url = proxy_url
        # OAuth2 clients — initialisés pour les rôles avec type oauth2_*
        # TYPE_CHECKING import only; runtime import deferred to avoid circular deps
        self._oauth_clients: dict[str, Any] = {}  # dict[str, OAuth2Client]
        for r in roles:
            if r.credentials and r.credentials.type in (
                "oauth2_password", "oauth2_client_credentials"
            ):
                from hdwp.core.experiment.oauth2_client import OAuth2Client
                self._oauth_clients[r.name] = OAuth2Client(r.credentials)

    async def __aenter__(self) -> Self:
        from hdwp.core.http_client import build_client
        for role in self._roles.values():
            self._clients[role.name] = build_client(proxy_url=self._proxy_url)
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close_all()

    async def close_all(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    def get_client(self, role_name: str) -> httpx.AsyncClient:
        if role_name not in self._clients:
            from hdwp.core.http_client import build_client
            self._clients[role_name] = build_client(proxy_url=self._proxy_url)
        return self._clients[role_name]

    def build_auth_headers(self, role_name: str) -> dict[str, str]:
        role = self._roles.get(role_name)
        if role is None or role.credentials is None:
            return {}
        return _cred_to_headers(role.credentials)

    def update_csrf(self, response: httpx.Response, role_name: str) -> None:
        """Extract and cache any CSRF token from response headers or cookies."""
        for header_name in CSRF_HEADER_NAMES:
            value = response.headers.get(header_name)
            if value:
                self._csrf_tokens[role_name] = value
                log.debug("csrf.updated", role=role_name, source="header", header=header_name)
                return

        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            for cookie_name in CSRF_COOKIE_NAMES:
                match = re.search(rf"{re.escape(cookie_name)}=([^;]+)", set_cookie, re.IGNORECASE)
                if match:
                    self._csrf_tokens[role_name] = match.group(1)
                    log.debug("csrf.updated", role=role_name, source="cookie", cookie=cookie_name)
                    return

    def inject_csrf(self, headers: dict[str, str], role_name: str) -> dict[str, str]:
        """Return new headers dict with CSRF token injected (does not mutate input)."""
        token = self._csrf_tokens.get(role_name)
        if not token:
            return headers
        return {**headers, "X-CSRF-Token": token}

    def prepare_headers(self, role_name: str, base_headers: dict[str, str]) -> dict[str, str]:
        """Auth headers + CSRF injection combined — use before sending mutated requests."""
        auth = self.build_auth_headers(role_name)
        return self.inject_csrf({**base_headers, **auth}, role_name)

    def check_token_expired(self, response: httpx.Response, role_name: str) -> None:
        """Raise TokenExpiredError if response signals auth failure."""
        if response.status_code == 401:
            raise TokenExpiredError(role_name)

    async def resolve_auth_headers(self, role_name: str) -> dict[str, str]:
        """
        Version async de build_auth_headers.
        Pour les rôles OAuth2 : acquiert/rafraîchit le token si nécessaire.
        Pour les autres types : délègue à build_auth_headers (sync).
        """
        if role_name in self._oauth_clients:
            try:
                token = await self._oauth_clients[role_name].get_token()
                return {"Authorization": f"Bearer {token}"}
            except Exception as exc:  # noqa: BLE001
                log.warning("oauth2.token_failed", role=role_name, error=str(exc))
                return {}
        return self.build_auth_headers(role_name)

    async def add_role(self, role: RoleConfig) -> None:
        """
        Dynamically add a role captured during the session (e.g. via proxy).
        Thread-safe: uses asyncio.Lock to prevent concurrent client dict mutation.
        """
        async with self._lock:
            if role.name in self._roles:
                return  # already registered — idempotent
            self._roles[role.name] = role
            from hdwp.core.http_client import build_client
            self._clients[role.name] = build_client(proxy_url=self._proxy_url)
            # Si OAuth2, créer le client OAuth2
            if role.credentials and role.credentials.type in (
                "oauth2_password", "oauth2_client_credentials"
            ):
                from hdwp.core.experiment.oauth2_client import OAuth2Client
                self._oauth_clients[role.name] = OAuth2Client(role.credentials)
        log.info("session.role_added", role=role.name)


def _cred_to_headers(cred: CredentialConfig) -> dict[str, str]:
    match cred.type:
        case "bearer":
            return {"Authorization": f"Bearer {cred.token}"} if cred.token else {}
        case "basic":
            if cred.username and cred.password:
                encoded = base64.b64encode(
                    f"{cred.username}:{cred.password}".encode()
                ).decode()
                return {"Authorization": f"Basic {encoded}"}
            return {}
        case "api_key":
            name = cred.header_name or "X-Api-Key"
            value = cred.header_value or cred.token or ""
            return {name: value} if value else {}
        case "cookie":
            return {"Cookie": cred.token} if cred.token else {}
    return {}
