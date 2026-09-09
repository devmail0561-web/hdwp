# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Stratégies de bypass WAF au niveau protocol (4 stratégies).

http2_smuggling: Pseudo-headers HTTP/2 injectés en HTTP/1.1.
websocket_upgrade: Headers Upgrade WS — certains WAFs skippent le DPI sur WS.
ipv6_bypass: Remplacement de l'adresse IP hôte par sa forme IPv6.
tls_fingerprint: Simulation d'un profil browser légitime (User-Agent + headers).
"""
from __future__ import annotations

import base64
import os
from typing import Any
from urllib.parse import urlparse, urlunparse

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.bypass_registry import BypassResult, BypassStrategy


def _http2_smuggling(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    parsed = urlparse(request.url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    new_headers = dict(request.headers)
    new_headers[":method"] = request.method
    new_headers[":path"] = path
    new_headers[":scheme"] = parsed.scheme or "https"
    new_headers[":authority"] = parsed.netloc
    new_headers["Transfer-Encoding"] = "chunked"
    new_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
    )


def _websocket_upgrade(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    ws_key = base64.b64encode(os.urandom(16)).decode()
    new_headers = dict(request.headers)
    new_headers["Upgrade"] = "websocket"
    new_headers["Connection"] = "Upgrade"
    new_headers["Sec-WebSocket-Key"] = ws_key
    new_headers["Sec-WebSocket-Version"] = "13"
    new_headers["Sec-WebSocket-Protocol"] = "permessage-deflate"

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
    )


def _ipv6_bypass(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    mode: str = params.get("mode", "loopback")
    parsed = urlparse(request.url)
    host = parsed.hostname or ""

    new_netloc: str | None = None

    if mode == "loopback":
        if host in ("127.0.0.1", "localhost"):
            port_part = f":{parsed.port}" if parsed.port else ""
            new_netloc = f"[::1]{port_part}"
    elif mode == "mapped":
        parts = host.split(".")
        if len(parts) == 4:
            try:
                a, b, c, d = (int(p) for p in parts)
                mapped = f"::ffff:{a * 256 + b:x}:{c * 256 + d:x}"
                port_part = f":{parsed.port}" if parsed.port else ""
                new_netloc = f"[{mapped}]{port_part}"
            except ValueError:
                pass

    if new_netloc is None:
        return BypassResult(request=request)

    new_url = urlunparse(parsed._replace(netloc=new_netloc))
    return BypassResult(
        request=request.model_copy(update={"url": new_url}),
    )


_BROWSER_PROFILES: dict[str, dict[str, str]] = {
    "chrome_latest": {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    "firefox_latest": {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
            "Gecko/20100101 Firefox/125.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    "safari_latest": {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.4.1 Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
}


def _tls_fingerprint(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    profile_name: str = params.get("profile", "chrome_latest")
    browser_headers = _BROWSER_PROFILES.get(profile_name, _BROWSER_PROFILES["chrome_latest"])
    new_headers = {**dict(request.headers), **browser_headers}

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
    )


PROTOCOL_STRATEGIES: list[BypassStrategy] = [
    BypassStrategy(
        name="http2_smuggling",
        category="protocol",
        apply=_http2_smuggling,
        description="Injecte des pseudo-headers HTTP/2 en HTTP/1.1 pour tromper les proxies WAF",
        risk_level="high",
    ),
    BypassStrategy(
        name="websocket_upgrade",
        category="protocol",
        apply=_websocket_upgrade,
        description="Headers Upgrade WS — WAFs qui skippent le DPI sur WebSocket",
        risk_level="medium",
    ),
    BypassStrategy(
        name="ipv6_bypass",
        category="protocol",
        apply=_ipv6_bypass,
        description="Remplace l'IP hôte par sa forme IPv6 (loopback ou IPv4-mapped)",
        risk_level="low",
    ),
    BypassStrategy(
        name="tls_fingerprint",
        category="protocol",
        apply=_tls_fingerprint,
        description="Simule un profil browser légitime (Chrome/Firefox/Safari)",
        risk_level="low",
    ),
]
