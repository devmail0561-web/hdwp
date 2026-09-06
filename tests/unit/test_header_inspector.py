# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from hdwp.core.model.schemas import NormalizedResponse
from hdwp.core.observation.header_inspector import HeaderInspector


def _make_response(headers: dict[str, str]) -> NormalizedResponse:
    return NormalizedResponse(status_code=200, headers=headers)


def test_missing_security_headers_detected() -> None:
    inspector = HeaderInspector()
    resp = _make_response({})
    # HSTS only checked for HTTPS targets
    tags = inspector.inspect(resp, request_url="https://example.com")
    assert "missing:HSTS" in tags
    assert "missing:CSP" in tags
    assert "missing:XFO" in tags
    assert "missing:XCTO" in tags
    assert "missing:XXP" in tags
    assert "missing:RP" in tags


def test_present_security_headers_not_flagged() -> None:
    inspector = HeaderInspector()
    resp = _make_response({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
    })
    tags = inspector.inspect(resp)
    missing_tags = [t for t in tags if t.startswith("missing:")]
    assert missing_tags == []


def test_server_header_info_disclosure() -> None:
    inspector = HeaderInspector()
    resp = _make_response({"server": "nginx/1.21.0"})
    tags = inspector.inspect(resp)
    assert "server:nginx/1.21.0" in tags


def test_x_powered_by_disclosure() -> None:
    inspector = HeaderInspector()
    resp = _make_response({"X-Powered-By": "Express"})
    tags = inspector.inspect(resp)
    assert "server:Express" in tags


def test_cookie_missing_flags() -> None:
    inspector = HeaderInspector()
    resp = _make_response({"Set-Cookie": "session=abc; Path=/"})
    tags = inspector.inspect(resp)
    assert "cookie:missing-httponly" in tags
    assert "cookie:missing-secure" in tags
    assert "cookie:missing-samesite" in tags


def test_cookie_with_all_flags() -> None:
    inspector = HeaderInspector()
    resp = _make_response({
        "Set-Cookie": "session=abc; HttpOnly; Secure; SameSite=Strict; Path=/"
    })
    tags = inspector.inspect(resp)
    cookie_tags = [t for t in tags if t.startswith("cookie:")]
    assert cookie_tags == []


def test_no_set_cookie_no_cookie_tags() -> None:
    inspector = HeaderInspector()
    resp = _make_response({"Content-Type": "text/html"})
    tags = inspector.inspect(resp)
    cookie_tags = [t for t in tags if t.startswith("cookie:")]
    assert cookie_tags == []
