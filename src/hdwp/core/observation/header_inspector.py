# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re

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

# Splits concatenated Set-Cookie header at cookie boundaries.
# httpx concatenates multiple Set-Cookie headers with ", " when cast to dict.
# Pattern: split at ", " followed by a cookie-name= pattern.
_COOKIE_SPLIT = re.compile(r",\s*(?=[A-Za-z0-9_-]+=)")


class HeaderInspector:
    def inspect(self, response: NormalizedResponse, request_url: str = "") -> list[str]:
        tags: list[str] = []
        lower_headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = request_url.startswith("https://")

        for header_key, tag_name in SECURITY_HEADERS.items():
            # HSTS only applies to HTTPS — skip for HTTP targets to avoid false positives
            if tag_name == "HSTS" and not is_https:
                continue
            if header_key not in lower_headers:
                tags.append(f"missing:{tag_name}")

        for header_key in SERVER_HEADERS:
            if header_key in lower_headers:
                tags.append(f"server:{lower_headers[header_key]}")

        set_cookie = lower_headers.get("set-cookie", "")
        if set_cookie:
            # Split into individual cookies before checking flags so that
            # a flag present on only one cookie doesn't mask its absence on another.
            cookies = _COOKIE_SPLIT.split(set_cookie)
            missing_flags: set[str] = set()
            for cookie in cookies:
                cookie_lower = cookie.lower()
                for flag in COOKIE_FLAGS:
                    if flag not in cookie_lower:
                        missing_flags.add(flag)
            for flag in sorted(missing_flags):
                tags.append(f"cookie:missing-{flag}")

        return tags
