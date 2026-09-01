# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import httpx
import pytest

from tests.fixtures.mock_server import VulnerableAppTransport


@pytest.fixture
def client() -> httpx.Client:
    return httpx.Client(transport=VulnerableAppTransport(), base_url="http://test")


# ── login ─────────────────────────────────────────────────────────────────────

def test_login_alice(client: httpx.Client) -> None:
    resp = client.post("/api/login", json={"username": "alice", "password": "secret_a"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token"] == "token_alice"
    assert data["user_id"] == 1


def test_login_bob(client: httpx.Client) -> None:
    resp = client.post("/api/login", json={"username": "bob", "password": "secret_b"})
    assert resp.status_code == 200
    assert resp.json()["token"] == "token_bob"


def test_login_wrong_password(client: httpx.Client) -> None:
    resp = client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client: httpx.Client) -> None:
    resp = client.post("/api/login", json={"username": "nobody", "password": "x"})
    assert resp.status_code == 401


# ── GET /api/users/{id} — BOLA ────────────────────────────────────────────────

def test_get_own_user(client: httpx.Client) -> None:
    resp = client.get("/api/users/1", headers={"Authorization": "Bearer token_alice"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Alice"


def test_bola_alice_accesses_bob(client: httpx.Client) -> None:
    """BOLA: Alice's token can access Bob's data."""
    resp = client.get("/api/users/2", headers={"Authorization": "Bearer token_alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Bob"
    assert data["id"] == 2


def test_get_user_no_token(client: httpx.Client) -> None:
    resp = client.get("/api/users/1")
    assert resp.status_code == 401


def test_get_user_not_found(client: httpx.Client) -> None:
    resp = client.get("/api/users/999", headers={"Authorization": "Bearer token_alice"})
    assert resp.status_code == 404


# ── GET /api/admin/users — AuthZ bypass ───────────────────────────────────────

def test_authz_bypass_alice_accesses_admin(client: httpx.Client) -> None:
    """AuthZ bypass: Alice (non-admin) can access admin endpoint."""
    resp = client.get("/api/admin/users", headers={"Authorization": "Bearer token_alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2


def test_admin_no_token(client: httpx.Client) -> None:
    resp = client.get("/api/admin/users")
    assert resp.status_code == 401


# ── GET /api/profile — correct implementation ─────────────────────────────────

def test_profile_alice_sees_only_herself(client: httpx.Client) -> None:
    resp = client.get("/api/profile", headers={"Authorization": "Bearer token_alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 1
    assert data["name"] == "Alice"


def test_profile_bob_sees_only_himself(client: httpx.Client) -> None:
    resp = client.get("/api/profile", headers={"Authorization": "Bearer token_bob"})
    assert resp.status_code == 200
    assert resp.json()["id"] == 2


def test_profile_no_token(client: httpx.Client) -> None:
    resp = client.get("/api/profile")
    assert resp.status_code == 401


def test_not_found(client: httpx.Client) -> None:
    resp = client.get("/api/nonexistent")
    assert resp.status_code == 404
