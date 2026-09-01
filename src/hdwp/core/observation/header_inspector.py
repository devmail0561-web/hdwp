# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import NormalizedResponse

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "XFO",
    "x-content-type-options": "XCTO",
    "x-xss-protection": "XXP",
    "referrer-policy": "RP",
}

SERVER_HEADERS = frozenset({"server", "x-powered-by"})
COOKIE_FLAGS = frozenset({"httponly", "secure", "samesite"})


class HeaderInspector:
    def inspect(self, response: NormalizedResponse) -> list[str]:
        tags: list[str] = []
        lower_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_key, tag_name in SECURITY_HEADERS.items():
            if header_key not in lower_headers:
                tags.append(f"missing:{tag_name}")

        for header_key in SERVER_HEADERS:
            if header_key in lower_headers:
                value = lower_headers[header_key]
                tags.append(f"server:{value}")

        set_cookie = lower_headers.get("set-cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            for flag in COOKIE_FLAGS:
                if flag not in cookie_lower:
                    tags.append(f"cookie:missing-{flag}")

        return tags
