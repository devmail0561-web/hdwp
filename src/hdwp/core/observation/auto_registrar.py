# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
AutoRegistrar: crée automatiquement des comptes de test.

Utilisé quand le pentesteur n'a qu'un compte (ou aucun) pour tester BOLA/IDOR.
Requiert allow_write=True dans le contexte.

Si la registration réussit, le moteur obtient 2 comptes distincts et peut
effectuer des tests d'identity_swap (BOLA cross-user).
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx
import structlog

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig

log = structlog.get_logger()

HDWP_TEST_DOMAIN = "hdwp-pentest.test"

REGISTRATION_PATHS = [
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/api/auth/register",
    "/api/auth/signup",
    "/api/users",
    "/api/v1/users",
    "/api/accounts",
    "/users/new",
]

# Templates corps de registration — essayés dans l'ordre
REGISTRATION_BODIES = [
    {"email": "{email}", "password": "{password}"},
    {"username": "{username}", "password": "{password}", "email": "{email}"},
    {"name": "{username}", "email": "{email}", "password": "{password}"},
    {"user": {"email": "{email}", "password": "{password}"}},
]

DELETE_PATH_TEMPLATES = [
    "/api/users/{id}",
    "/api/accounts/{id}",
    "/users/{id}",
]


class AutoRegistrar:
    """
    Tente de créer des comptes de test en cherchant les endpoints de registration.

    Nettoyage : supprime les comptes créés via cleanup() en fin de session.
    """

    def __init__(
        self,
        session_manager: Any,
        scope_guard: Any,
        context: Any,
    ) -> None:
        self._session_manager = session_manager
        self._scope_guard = scope_guard
        self._context = context
        self._registered_ids: list[Any] = []
        self._created_roles: list[Any] = []  # pour cleanup avec auth

    async def try_register_test_accounts(self) -> list[RoleConfig]:
        """
        Tente de créer 2 comptes de test.
        Retourne la liste des RoleConfig créés (vide si aucun endpoint trouvé).
        """
        from hdwp.core.context.scope_guard import ScopeVerdict

        created: list[RoleConfig] = []
        base = self._context.base_url.rstrip("/")

        for path in REGISTRATION_PATHS:
            if len(created) >= 2:
                break
            url = f"{base}{path}"
            verdict = self._scope_guard.check(url, "POST")
            if verdict != ScopeVerdict.ALLOWED:
                continue

            needed = 2 - len(created)
            for idx in range(needed):
                role = await self._register_one(url, len(created) + idx + 1)
                if role is not None:
                    created.append(role)

        if created:
            log.info("auto_registrar.accounts_created", count=len(created))
        else:
            log.debug("auto_registrar.no_registration_endpoint_found")
        return created

    async def _register_one(self, url: str, idx: int) -> RoleConfig | None:
        suffix = uuid.uuid4().hex[:6]
        username = f"hdwp_{idx}_{suffix}"
        email = f"{username}@{HDWP_TEST_DOMAIN}"
        # Politique de mot de passe permissive : majuscule, chiffre, spécial
        password = f"Hdwp@{suffix.upper()}1"

        for template in REGISTRATION_BODIES:
            body = {
                k: v.format(username=username, email=email, password=password)
                if isinstance(v, str) else
                {
                    sk: sv.format(username=username, email=email, password=password)
                    for sk, sv in v.items()
                }
                for k, v in template.items()
            }
            result = await self._try_post(url, body)
            if result is not None:
                role = self._extract_role(result, idx)
                if role is not None:
                    uid = (
                        result.get("id")
                        or result.get("user_id")
                        or result.get("userId")
                    )
                    self._registered_ids.append(uid)
                    self._created_roles.append(role)
                    log.info("auto_registrar.role_created", role=role.name, url=url)
                    return role
        return None

    async def _try_post(self, url: str, body: dict) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                resp = await client.post(url, json=body)
                if resp.status_code in (200, 201):
                    try:
                        return resp.json()
                    except Exception:  # noqa: BLE001
                        return {"_raw": resp.text}
        except Exception:  # noqa: BLE001, S110
            pass
        return None

    def _extract_role(self, result: dict, idx: int) -> RoleConfig | None:
        """Extrait le token depuis la réponse de registration."""
        token = (
            result.get("token")
            or result.get("access_token")
            or result.get("auth_token")
            or result.get("jwt")
        )
        if token and isinstance(token, str) and len(token) > 8:
            return RoleConfig(
                name=f"auto_test_{idx}",
                credentials=CredentialConfig(type="bearer", token=token),
            )
        return None

    async def cleanup(self) -> None:
        """Supprime les comptes créés en fin de session (best-effort)."""
        from hdwp.core.context.scope_guard import ScopeVerdict

        base = self._context.base_url.rstrip("/")
        for uid in self._registered_ids:
            if uid is None:
                continue
            for path_tpl in DELETE_PATH_TEMPLATES:
                url = f"{base}{path_tpl.replace('{id}', str(uid))}"
                verdict = self._scope_guard.check(url, "DELETE")
                if verdict == ScopeVerdict.ALLOWED:
                    try:
                        # Utiliser les credentials du rôle créé pour l'auth du DELETE
                        auth_headers: dict[str, str] = {}
                        if self._created_roles:
                            cred = self._created_roles[0].credentials
                            if cred and cred.token:
                                auth_headers = {"Authorization": f"Bearer {cred.token}"}
                        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                            await client.delete(url, headers=auth_headers)
                        log.debug("auto_registrar.account_deleted", uid=uid)
                        break
                    except Exception:  # noqa: BLE001, S110
                        pass
