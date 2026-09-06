# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Utilitaires pour le ChainEngine : extraction de valeurs et injection de contexte."""
from __future__ import annotations

from typing import Any

from hdwp.core.model.schemas import NormalizedRequest


def extract_value(body: Any, path: str) -> Any:
    """Extraction dot-notation simple : 'token', 'data.id', 'items.0.name'."""
    if not path or body is None:
        return None
    parts = path.split(".", 1)
    if isinstance(body, dict):
        val = body.get(parts[0])
        return extract_value(val, parts[1]) if len(parts) > 1 else val
    if isinstance(body, list) and parts[0].isdigit():
        idx = int(parts[0])
        val = body[idx] if idx < len(body) else None
        return extract_value(val, parts[1]) if len(parts) > 1 else val
    return None


def inject_context(
    request: NormalizedRequest,
    context: dict[str, Any],
    inject_spec: dict[str, str],
) -> NormalizedRequest:
    """Injecte les valeurs de contexte dans la requête selon inject_spec.

    inject_spec maps param_name → context_var_name.
    Supports injection dans query_params, body (dict), headers, et URL path.
    """
    if not inject_spec or not context:
        return request

    new_query = dict(request.query_params or {})
    new_body = dict(request.body) if isinstance(request.body, dict) else request.body
    new_headers = dict(request.headers or {})
    new_url = request.url

    for param_name, var_name in inject_spec.items():
        value = context.get(var_name)
        if value is None:
            continue
        str_value = str(value)

        if param_name.startswith("header:"):
            header_key = param_name[7:]
            new_headers[header_key] = str_value
        elif param_name.startswith("url:"):
            placeholder = param_name[4:]
            new_url = new_url.replace(f"{{{placeholder}}}", str_value)
        elif isinstance(new_body, dict) and param_name in new_body:
            new_body[param_name] = value
        elif param_name in new_query:
            new_query[param_name] = str_value
        else:
            # Défaut : injecter dans les query params
            new_query[param_name] = str_value

    return NormalizedRequest(
        method=request.method,
        url=new_url,
        headers=new_headers,
        body=new_body,
        query_params=new_query,
        path_params=request.path_params,
    )
