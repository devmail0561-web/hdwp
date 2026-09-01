# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
JSExtractor: extrait les endpoints API depuis les fichiers JavaScript.

Stratégies :
1. Regex sur les appels fetch/axios
2. Extraction des routes depuis les configs d'API (baseURL, url, path)
3. Chaînes ressemblant à des endpoints API
4. Normalisation : ${...} → {param}
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

ENDPOINT_PATTERNS = [
    # fetch('/api/users')  |  fetch(`/api/users/${id}`)
    re.compile(
        r"""(?:fetch|axios\.[a-z]+)\(\s*[`'"](/[a-zA-Z0-9/_\-{}$\[\].]+"""
        r"""(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
    ),
    # url: '/api/users'  |  baseURL: '/api'  |  endpoint: '/api/v1'
    re.compile(
        r"""(?:url|path|endpoint|href|baseURL|BASE_URL)\s*[:=]\s*[`'"]([/a-zA-Z0-9/_\-{}]+)[`'"]"""
    ),
    # "/api/users/42"  "/v1/products"  "/graphql" — chaînes standalone
    re.compile(
        r"""[`'"](/(?:api|v[0-9]+|rest|graphql)/[a-zA-Z0-9/_\-{}$.]+)[`'"]"""
    ),
]

_TEMPLATE_VAR = re.compile(r"\$\{[^}]+\}")


class JSExtractor:
    """Extrait les endpoints API depuis le source JavaScript."""

    def extract_endpoints(self, js_source: str, base_url: str) -> list[str]:
        """
        Retourne une liste d'URLs absolues extraites du JS.

        Les template literals `${id}` sont normalisés vers `{param}`.
        Les faux positifs évidents (trop longs, extensions statiques) sont filtrés.
        """
        endpoints: set[str] = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_source):
                path = _TEMPLATE_VAR.sub("{param}", match.group(1))
                if _is_valid_endpoint(path):
                    endpoints.add(path)

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return sorted(f"{base}{p}" for p in endpoints)


def _is_valid_endpoint(path: str) -> bool:
    """Filtre les faux positifs courants."""
    if len(path) <= 3:
        return False
    if path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".map")):
        return False
    return path.count("/") <= 6
