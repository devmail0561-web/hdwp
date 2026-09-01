# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import copy
from typing import Any

REDACTED = "[REDACTED]"

DEFAULT_SENSITIVE_KEYS: set[str] = {
    "authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
    "x-csrf-token",
}


def filter_credentials(
    data: dict[str, Any],
    sensitive_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Deep-walk a dict and redact values whose keys match sensitive header names.

    Only keys inside dicts keyed by "headers" are checked, so body content is
    left untouched.  Returns a new dict — the input is never mutated.
    """
    sensitive: set[str] = DEFAULT_SENSITIVE_KEYS.copy()
    if sensitive_patterns:
        sensitive.update(k.lower() for k in sensitive_patterns)

    return _walk(copy.deepcopy(data), sensitive, inside_headers=False)


def _walk(obj: Any, sensitive: set[str], *, inside_headers: bool) -> Any:
    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for key, value in obj.items():
            is_headers_key = key.lower() == "headers"
            if inside_headers and key.lower() in sensitive:
                result[key] = REDACTED
            else:
                result[key] = _walk(
                    value,
                    sensitive,
                    inside_headers=inside_headers or is_headers_key,
                )
        return result
    if isinstance(obj, list):
        return [_walk(item, sensitive, inside_headers=inside_headers) for item in obj]
    return obj
