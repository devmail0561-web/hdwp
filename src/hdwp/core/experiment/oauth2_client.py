# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
OAuth2Client: acquiert et rafraîchit les tokens OAuth2.

Supporte :
- oauth2_password (grant_type=password) : username + password → access_token
- oauth2_client_credentials : client_id + client_secret → access_token

La clé API n'est jamais stockée en clair dans le YAML — toujours via ${ENV_VAR}.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hdwp.core.context.config_schema import CredentialConfig

log = structlog.get_logger()


class OAuth2Error(Exception):
    """Erreur d'acquisition ou de refresh d'un token OAuth2."""


class OAuth2Client:
    """
    Client OAuth2 qui gère l'acquisition et le cache des tokens.

    Utilisation::

        client = OAuth2Client(cred)
        token = await client.get_token()  # acquiert si nécessaire
        headers = {"Authorization": f"Bearer {token}"}
    """

    def __init__(self, cred: CredentialConfig) -> None:
        self._cred = cred
        self._access_token: str | None = None
        self._expires_at: float = 0.0

    async def get_token(self) -> str:
        """Retourne un token valide, en acquérant si nécessaire (cache 30s de marge)."""
        if self._access_token and time.monotonic() < self._expires_at - 30:
            return self._access_token
        return await self._acquire_token()

    async def force_refresh(self) -> str:
        """Force l'acquisition d'un nouveau token (ignore le cache)."""
        self._expires_at = 0.0
        self._access_token = None
        return await self._acquire_token()

    async def _acquire_token(self) -> str:
        cred = self._cred
        if not cred.token_endpoint:
            raise OAuth2Error("token_endpoint requis pour OAuth2 (rôle inconnu)")

        if cred.type == "oauth2_password":
            data: dict[str, str] = {
                "grant_type": "password",
                "username": cred.username or "",
                "password": cred.password or "",
            }
        else:  # oauth2_client_credentials
            data = {"grant_type": "client_credentials"}

        if cred.client_id:
            data["client_id"] = cred.client_id
        if cred.client_secret:
            data["client_secret"] = cred.client_secret
        if cred.scope:
            data["scope"] = cred.scope

        from hdwp.core.http_client import build_client
        async with build_client(timeout=15.0) as client:
            try:
                resp = await client.post(cred.token_endpoint, data=data)
                # MFA/2FA challenge — complete OTP step if totp_secret is configured
                if cred.totp_secret:
                    from hdwp.core.experiment.mfa_handler import (
                        detect_mfa_challenge,
                        resolve_mfa_step,
                    )
                    challenge = detect_mfa_challenge(resp)
                    if challenge:
                        mfa_resp = await resolve_mfa_step(
                            client, challenge, cred.totp_secret, resp
                        )
                        if mfa_resp is not None and mfa_resp.status_code < 400:
                            resp = mfa_resp
                resp.raise_for_status()
                token_data: dict[str, Any] = resp.json()
            except Exception as exc:
                raise OAuth2Error(f"Échec acquisition token OAuth2 : {exc}") from exc

        token = token_data.get("access_token", "")
        if not token:
            raise OAuth2Error("Réponse OAuth2 sans access_token")

        self._access_token = token
        expires_in = float(token_data.get("expires_in", 3600))
        self._expires_at = time.monotonic() + expires_in

        if "refresh_token" in token_data:
            self._cred.refresh_token = token_data["refresh_token"]

        log.info("oauth2.token_acquired", expires_in=int(expires_in), type=cred.type)
        return self._access_token
