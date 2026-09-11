# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MFA/2FA challenge detection and resolution.

Detects multi-factor authentication challenges in HTTP responses and completes
the second step (OTP submission) when a TOTP secret is available.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import structlog

log = structlog.get_logger()

_MFA_BODY_KEYS = frozenset({
    "mfa_required", "otp_required", "totp_required",
    "two_factor_required", "step", "requires_otp",
    "challenge_type", "mfa_token",
})

_MFA_HEADERS = frozenset({"x-mfa-required", "x-2fa-required", "x-otp-required"})


@dataclass
class MfaChallenge:
    challenge_type: str  # "totp" | "hotp" | "otp_code" | "unknown"
    submit_url: str | None = None
    otp_field: str = "otp"
    extra_fields: dict = field(default_factory=dict)


def detect_mfa_challenge(response: httpx.Response) -> MfaChallenge | None:
    """Return MfaChallenge if response signals a 2FA challenge, else None."""
    # Signal 1 : explicit header
    for h in _MFA_HEADERS:
        if h in response.headers:
            return MfaChallenge(challenge_type="unknown")

    # Signal 2 : 202 + known MFA key in JSON body
    if response.status_code == 202:
        try:
            body = response.json()
            if isinstance(body, dict) and _MFA_BODY_KEYS & body.keys():
                return _parse_mfa_body(body)
        except Exception:
            pass

    # Signal 3 : any status + known MFA key in JSON body
    try:
        body = response.json()
        if isinstance(body, dict) and _MFA_BODY_KEYS & body.keys():
            return _parse_mfa_body(body)
    except Exception:
        pass

    return None


def _parse_mfa_body(body: dict) -> MfaChallenge:
    challenge_type = str(body.get("challenge_type", body.get("mfa_type", "unknown")))
    submit_url = body.get("submit_url") or body.get("verify_url")
    otp_field = body.get("otp_field", "otp")
    return MfaChallenge(
        challenge_type=challenge_type,
        submit_url=submit_url,
        otp_field=str(otp_field),
    )


def generate_totp(secret: str) -> str:
    """Generate a TOTP code from a base32 secret. Requires pyotp."""
    try:
        import pyotp
        return pyotp.TOTP(secret).now()
    except ImportError as exc:
        raise RuntimeError(
            "pyotp is required for TOTP generation: pip install pyotp"
        ) from exc


def _guess_submit_url(login_response: httpx.Response) -> str | None:
    loc = login_response.headers.get("location")
    if loc:
        return loc
    try:
        body = login_response.json()
        for key in ("next", "redirect", "verify_url", "submit_url"):
            if key in body:
                return str(body[key])
    except Exception:
        pass
    return None


async def resolve_mfa_step(
    client: httpx.AsyncClient,
    challenge: MfaChallenge,
    totp_secret: str,
    login_response: httpx.Response,
) -> httpx.Response | None:
    """
    Complete a 2FA step by POSTing the OTP code.
    Returns the final response, or None if the submit URL cannot be determined.
    """
    code = generate_totp(totp_secret)
    submit_url = challenge.submit_url or _guess_submit_url(login_response)
    if not submit_url:
        log.warning("mfa.submit_url_unknown")
        return None

    body = {challenge.otp_field: code, **challenge.extra_fields}
    try:
        resp = await client.post(submit_url, json=body)
        log.info("mfa.otp_submitted", status=resp.status_code)
        return resp
    except Exception as exc:
        log.warning("mfa.submit_failed", error=str(exc))
        return None
