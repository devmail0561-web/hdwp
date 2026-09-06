# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from hdwp.core.model.schemas import NormalizedRequest, NormalizedResponse

CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "proxy-authorization",
})

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.IGNORECASE
)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in CREDENTIAL_HEADERS:
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


def _extract_path_params(path: str) -> dict[str, str]:
    params: dict[str, str] = {}
    idx = 0
    for segment in path.strip("/").split("/"):
        if _NUMERIC_SEGMENT.match(segment) or _UUID_SEGMENT.match(segment):
            params[f"param_{idx}"] = segment
            idx += 1
    return params


def normalize_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: Any = None,
) -> NormalizedRequest:
    parsed = urlparse(url)
    query_params: dict[str, str] = {}
    for k, v_list in parse_qs(parsed.query).items():
        query_params[k] = v_list[0] if len(v_list) == 1 else ",".join(v_list)

    safe_headers = _redact_headers(headers or {})
    path_params = _extract_path_params(parsed.path)

    # Decode form-encoded string bodies into structured dict.
    # Guard: skip if the body looks like JSON (starts with { or [) to avoid
    # misinterpreting JSON strings that happen to contain '=' and '&' characters
    # (e.g. {"url": "https://x.com?a=1&b=2"}).
    parsed_body = body
    _body_stripped = body.lstrip() if isinstance(body, str) else ""
    _looks_like_json = _body_stripped[:1] in ("{", "[")
    if isinstance(body, str) and not _looks_like_json and "&" in body and "=" in body:
        try:
            parsed_body = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        except Exception:  # noqa: BLE001
            parsed_body = body

    return NormalizedRequest(
        method=method.upper(),
        url=url,
        headers=safe_headers,
        body=parsed_body,
        query_params=query_params,
        path_params=path_params,
    )


def normalize_response(
    status_code: int,
    headers: dict[str, str] | None = None,
    body: Any = None,
    timing_ms: float = 0.0,
) -> NormalizedResponse:
    hdrs = headers or {}
    content_type = hdrs.get("content-type", hdrs.get("Content-Type"))

    parsed_body = body
    has_json_ct = bool(content_type and "application/json" in content_type)
    looks_like_json = isinstance(body, (str, bytes)) and (
        (isinstance(body, str) and body.lstrip()[:1] in ("{", "["))
        or (isinstance(body, bytes) and body.lstrip()[:1] in (b"{", b"["))
    )
    if isinstance(body, (str, bytes)) and (has_json_ct or looks_like_json):
        try:
            parsed_body = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            parsed_body = body

    return NormalizedResponse(
        status_code=status_code,
        headers=hdrs,
        body=parsed_body,
        content_type=content_type,
        timing_ms=timing_ms,
    )
