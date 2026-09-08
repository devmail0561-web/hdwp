# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
import re
from typing import Any

from hdwp.core.model.schemas import NormalizedResponse

_SQL_RE = re.compile(r"syntax error|ORA-\d+|MySQL.*Error|pg_exception", re.IGNORECASE)
_STACK_RE = re.compile(r"at\s+\w+\.\w+\(|Traceback\s+\(most recent", re.IGNORECASE)
_DISCLOSE_RE = re.compile(r"root:|/etc/passwd|Windows\\System32", re.IGNORECASE)
_TEMPLATE_RE = re.compile(r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>")

_SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "access-control-allow-origin",
    "cache-control",
]


def _body_depth_keys(body: Any, _depth: int = 0) -> tuple[int, int]:
    if isinstance(body, dict):
        keys = len(body)
        max_depth = _depth
        total_keys = keys
        for v in body.values():
            d, k = _body_depth_keys(v, _depth + 1)
            max_depth = max(max_depth, d)
            total_keys += k
        return max_depth, total_keys
    if isinstance(body, list):
        if not body:
            return _depth, 0
        max_depth = _depth
        total_keys = 0
        for item in body[:5]:
            d, k = _body_depth_keys(item, _depth + 1)
            max_depth = max(max_depth, d)
            total_keys += k
        return max_depth, total_keys
    return _depth, 0


def _body_to_str(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body)
    except (TypeError, ValueError):
        return str(body)


class ResponseEmbedder:
    """
    Encode une NormalizedResponse en vecteur de features de dimension fixe 22.

    Layout :
      [0:5]   status category one-hot (1xx / 2xx / 3xx / 4xx / 5xx)
      [5]     timing_ms normalisé (/ 5000.0, clamped [0, 1])
      [6:10]  body type one-hot (null / dict / list / str)
      [10]    profondeur body normalisée (/ 5.0, clamped [0, 1])
      [11]    nombre de clés JSON normalisé (/ 50.0, clamped [0, 1])
      [12:18] présence security headers (CSP, HSTS, X-Frame, X-Content-Type, ACAO, Cache-Control)
      [18]    signal sql_error
      [19]    signal stack_trace
      [20]    signal disclosure
      [21]    signal template_injection
    """

    DIM: int = 22

    def embed(self, response: NormalizedResponse) -> list[float]:
        vec: list[float] = []

        # [0:5] status category
        sc = response.status_code
        vec += [
            1.0 if 100 <= sc < 200 else 0.0,
            1.0 if 200 <= sc < 300 else 0.0,
            1.0 if 300 <= sc < 400 else 0.0,
            1.0 if 400 <= sc < 500 else 0.0,
            1.0 if 500 <= sc < 600 else 0.0,
        ]

        # [5] timing
        vec.append(min(response.timing_ms / 5000.0, 1.0))

        # [6:10] body type one-hot
        body = response.body
        vec += [
            1.0 if body is None else 0.0,
            1.0 if isinstance(body, dict) else 0.0,
            1.0 if isinstance(body, list) else 0.0,
            1.0 if isinstance(body, str) else 0.0,
        ]

        # [10:12] depth + key count
        depth, key_count = _body_depth_keys(body)
        vec.append(min(depth / 5.0, 1.0))
        vec.append(min(key_count / 50.0, 1.0))

        # [12:18] security headers
        headers_lower = {k.lower(): v for k, v in (response.headers or {}).items()}
        vec += [1.0 if h in headers_lower else 0.0 for h in _SECURITY_HEADERS]

        # [18:22] error signals
        body_str = _body_to_str(body)
        vec += [
            1.0 if _SQL_RE.search(body_str) else 0.0,
            1.0 if _STACK_RE.search(body_str) else 0.0,
            1.0 if _DISCLOSE_RE.search(body_str) else 0.0,
            1.0 if _TEMPLATE_RE.search(body_str) else 0.0,
        ]

        assert len(vec) == self.DIM, f"ResponseEmbedder: dim={len(vec)} != {self.DIM}"
        return vec
