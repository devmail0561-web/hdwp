# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from hdwp.core.experiment.jwt_mutator import (
    _b64url_encode,
    decode_jwt_insecure,
    forge_alg_none,
    forge_expired,
    try_weak_secrets,
)


def _make_jwt(payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def test_decode_jwt_insecure_valid():
    payload = {"sub": "user1", "exp": 9999999999}
    token = _make_jwt(payload)
    result = decode_jwt_insecure(token)
    assert result is not None
    header, decoded_payload, sig = result
    assert header["alg"] == "HS256"
    assert decoded_payload["sub"] == "user1"


def test_decode_jwt_insecure_invalid_format():
    assert decode_jwt_insecure("not.a.valid.jwt.token.parts") is None
    assert decode_jwt_insecure("only_two.parts") is None
    assert decode_jwt_insecure("bad!@#.payload!.sig") is None


def test_forge_alg_none_creates_unsigned_token():
    token = _make_jwt({"sub": "user1"})
    forged = forge_alg_none(token)
    assert forged is not None
    parts = forged.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # no signature
    # Header alg is none
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "none"


def test_forge_alg_none_preserves_payload():
    payload = {"sub": "user1", "role": "user"}
    token = _make_jwt(payload)
    forged = forge_alg_none(token)
    assert forged is not None
    parts = forged.split(".")
    decoded_payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert decoded_payload["sub"] == "user1"
    assert decoded_payload["role"] == "user"


def test_forge_alg_none_invalid_token():
    assert forge_alg_none("invalid") is None
    assert forge_alg_none("only.two") is None


def test_forge_expired_sets_past_exp():
    token = _make_jwt({"sub": "user1", "exp": int(time.time()) + 3600})
    forged = forge_expired(token, seconds_ago=86400)
    assert forged is not None
    parts = forged.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload["exp"] < int(time.time())


def test_forge_expired_keeps_original_signature():
    token = _make_jwt({"sub": "user1"})
    orig_parts = token.split(".")
    forged = forge_expired(token)
    assert forged is not None
    forged_parts = forged.split(".")
    assert forged_parts[2] == orig_parts[2]  # same (now invalid) signature
    assert forged_parts[0] == orig_parts[0]  # same header


def test_try_weak_secrets_finds_known_secret():
    token = _make_jwt({"sub": "user1", "role": "user"}, secret="secret")
    result = try_weak_secrets(token)
    assert result is not None
    parts = result.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload.get("admin") is True
    assert payload.get("role") == "admin"


def test_try_weak_secrets_returns_none_for_strong_secret():
    token = _make_jwt({"sub": "user1"}, secret="thisIsAVeryLongAndSecureSecret123!@#")
    result = try_weak_secrets(token)
    assert result is None


def test_try_weak_secrets_returns_none_for_non_hs256():
    token = _make_jwt({"sub": "user1"}, alg="RS256")
    # Manually create a fake RS256 token (just check alg check works)
    result = try_weak_secrets(token)
    # RS256 not supported → None
    assert result is None
