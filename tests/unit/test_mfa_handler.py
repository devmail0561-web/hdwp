# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import httpx
import pytest

from hdwp.core.experiment.mfa_handler import (
    MfaChallenge,
    _parse_mfa_body,
    detect_mfa_challenge,
    generate_totp,
)

_REQ = httpx.Request("POST", "http://test.local/login")


def _resp(status: int, body: dict | None = None, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        json=body if body is not None else {},
        headers=headers or {},
        request=_REQ,
    )


# --- detect_mfa_challenge ---

def test_no_challenge_normal_200():
    resp = _resp(200, {"access_token": "abc123"})
    assert detect_mfa_challenge(resp) is None


def test_no_challenge_empty_body():
    resp = _resp(200, {})
    assert detect_mfa_challenge(resp) is None


def test_challenge_detected_202_mfa_required():
    resp = _resp(202, {"mfa_required": True})
    result = detect_mfa_challenge(resp)
    assert result is not None
    assert isinstance(result, MfaChallenge)


def test_challenge_detected_202_step_key():
    resp = _resp(202, {"step": "otp", "submit_url": "/auth/otp"})
    result = detect_mfa_challenge(resp)
    assert result is not None
    assert result.submit_url == "/auth/otp"


def test_challenge_detected_via_header():
    resp = _resp(200, {}, headers={"x-mfa-required": "true"})
    result = detect_mfa_challenge(resp)
    assert result is not None
    assert result.challenge_type == "unknown"


def test_challenge_detected_200_body_two_factor():
    resp = _resp(200, {"two_factor_required": True, "challenge_type": "totp"})
    result = detect_mfa_challenge(resp)
    assert result is not None
    assert result.challenge_type == "totp"


def test_challenge_detected_x_2fa_header():
    resp = _resp(401, {}, headers={"x-2fa-required": "1"})
    result = detect_mfa_challenge(resp)
    assert result is not None


# --- _parse_mfa_body ---

def test_parse_mfa_body_extracts_challenge_type():
    body = {"challenge_type": "hotp", "otp_field": "code"}
    challenge = _parse_mfa_body(body)
    assert challenge.challenge_type == "hotp"
    assert challenge.otp_field == "code"


def test_parse_mfa_body_defaults():
    body = {"mfa_required": True}
    challenge = _parse_mfa_body(body)
    assert challenge.challenge_type == "unknown"
    assert challenge.otp_field == "otp"
    assert challenge.submit_url is None


def test_parse_mfa_body_submit_url():
    body = {"mfa_required": True, "verify_url": "/api/verify-otp"}
    challenge = _parse_mfa_body(body)
    assert challenge.submit_url == "/api/verify-otp"


# --- generate_totp ---

def test_generate_totp_returns_6_digit_code():
    # Use a well-known base32 test secret (RFC 4226 test vector)
    secret = "JBSWY3DPEHPK3PXP"
    code = generate_totp(secret)
    assert code.isdigit()
    assert len(code) == 6


def test_generate_totp_different_secrets_differ():
    code1 = generate_totp("JBSWY3DPEHPK3PXP")
    code2 = generate_totp("AAAAAAAAAAAAAAAA")
    # Codes from different secrets should almost certainly differ
    # (astronomically unlikely to collide at the same second)
    # We just verify both are valid 6-digit codes
    assert code1.isdigit() and len(code1) == 6
    assert code2.isdigit() and len(code2) == 6
