# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Mock vulnerable HTTP server for integration tests.

Implements two deliberate vulnerabilities:
1. BOLA on GET /api/users/{id}        — no ownership check
2. AuthZ bypass on GET /api/admin/users — no role check
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

USERS_DB: dict[int, dict[str, Any]] = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com"},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com"},
}

TOKENS: dict[str, int] = {
    "token_alice": 1,
    "token_bob":   2,
    "token_admin": 0,
}

CREDENTIALS: dict[tuple[str, str], str] = {
    ("alice", "secret_a"):     "token_alice",
    ("bob",   "secret_b"):     "token_bob",
    ("admin", "secret_admin"): "token_admin",
}


def _json_response(data: Any, status: int = 200) -> httpx.Response:
    body = json.dumps(data).encode()
    return httpx.Response(
        status_code=status,
        headers={"content-type": "application/json"},
        content=body,
    )


def _extract_token(request: httpx.Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def _get_user_id(request: httpx.Request) -> int | None:
    token = _extract_token(request)
    return TOKENS.get(token) if token else None  # type: ignore[arg-type]


class VulnerableAppTransport(httpx.BaseTransport):
    """
    Synchronous httpx transport simulating a vulnerable web application.
    Use with httpx.Client(transport=VulnerableAppTransport()).
    """

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method.upper()

        if method == "POST" and path == "/api/login":
            return self._handle_login(request)

        m = re.match(r"^/api/users/(\d+)$", path)
        if method == "GET" and m:
            return self._handle_get_user(request, int(m.group(1)))

        if method == "GET" and path == "/api/admin/users":
            return self._handle_admin_users(request)

        if method == "GET" and path == "/api/profile":
            return self._handle_profile(request)

        if method == "GET" and path.startswith("/api/search"):
            return self._handle_search(request)

        if method == "GET" and path.startswith("/api/greet"):
            return self._handle_greet(request)

        if method == "GET" and path in ("/", "/index.html"):
            return self._handle_homepage(request)

        return _json_response({"error": "not found"}, 404)

    def _handle_homepage(self, _request: httpx.Request) -> httpx.Response:
        """Page d'accueil HTML avec liens vers les endpoints API — permet au crawler de les découvrir."""
        html = """<!DOCTYPE html>
<html>
<head><title>App</title></head>
<body>
  <h1>Application</h1>
  <nav>
    <a href="/api/users/1">Mon profil</a>
    <a href="/api/users/2">Utilisateur 2</a>
    <a href="/api/admin/users">Administration</a>
    <a href="/api/profile">Mon compte</a>
    <a href="/api/search?q=test">Recherche</a>
  </nav>
</body>
</html>"""
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=html.encode(),
        )

    def _handle_login(self, request: httpx.Request) -> httpx.Response:
        try:
            body = json.loads(request.content)
            username = body.get("username", "")
            password = body.get("password", "")
        except (json.JSONDecodeError, AttributeError):
            return _json_response({"error": "bad request"}, 400)

        token = CREDENTIALS.get((username, password))
        if token is None:
            return _json_response({"error": "invalid credentials"}, 401)

        return _json_response({"token": token, "user_id": TOKENS[token]})

    def _handle_get_user(self, request: httpx.Request, user_id: int) -> httpx.Response:
        """BOLA: returns any user's data without checking token ownership."""
        if _get_user_id(request) is None:
            return _json_response({"error": "unauthorized"}, 401)
        user = USERS_DB.get(user_id)
        if user is None:
            return _json_response({"error": "not found"}, 404)
        # DELIBERATE BOLA: no ownership check
        return _json_response(user)

    def _handle_admin_users(self, request: httpx.Request) -> httpx.Response:
        """AuthZ bypass: accessible to any authenticated user."""
        if _get_user_id(request) is None:
            return _json_response({"error": "unauthorized"}, 401)
        # DELIBERATE AuthZ bypass: should require admin role
        return _json_response(list(USERS_DB.values()))

    def _handle_profile(self, request: httpx.Request) -> httpx.Response:
        """Correct: returns only the requester's own data."""
        requester_id = _get_user_id(request)
        if requester_id is None:
            return _json_response({"error": "unauthorized"}, 401)
        user = USERS_DB.get(requester_id)
        if user is None:
            return _json_response({"error": "not found"}, 404)
        return _json_response(user)

    def _handle_search(self, request: httpx.Request) -> httpx.Response:
        """DELIBERATE SQLi: unsanitised query parameter reflected in SQL error."""
        q = request.url.params.get("q", "")
        if "'" in q or '"' in q or "--" in q:
            return _json_response(
                {"error": f"You have an error in your SQL syntax near '{q}'"},
                status=500,
            )
        return _json_response({"results": [], "query": q})

    def _handle_greet(self, request: httpx.Request) -> httpx.Response:
        """DELIBERATE XSS: user-supplied name reflected unencoded in HTML response."""
        name = request.url.params.get("name", "World")
        html_body = f"<h1>Hello, {name}!</h1>"
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=html_body.encode(),
        )


class AsyncVulnerableAppTransport(httpx.AsyncBaseTransport):
    """
    Async version of VulnerableAppTransport.
    Use with httpx.AsyncClient(transport=AsyncVulnerableAppTransport()).
    """

    _sync = VulnerableAppTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._sync.handle_request(request)
