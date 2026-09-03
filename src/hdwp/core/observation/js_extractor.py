# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
JSExtractor: extrait les endpoints API depuis les fichiers JavaScript.

Stratégies :
1. fetch() / window.fetch()
2. axios.get/post/put/delete/patch + axios.create({ baseURL })
3. XMLHttpRequest.open()
4. jQuery $.ajax / $.get / $.post / $.getJSON
5. WebSocket / new WebSocket
6. Chaînes URL standalone avec préfixe API reconnu
7. Attributs url/path/endpoint/href dans des objets de config
8. Normalisation des template literals ${...} → {param}
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_TEMPLATE_VAR = re.compile(r"\$\{[^}]+\}")

# ── fetch() ─────────────────────────────────────────────────────────────────
_P_FETCH = re.compile(
    r"""(?:window\.)?fetch\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)

# ── axios direct calls: axios.get('/api/...') ────────────────────────────────
_P_AXIOS_DIRECT = re.compile(
    r"""axios\.[a-z]+\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)

# ── axios.create({ baseURL: '/api' }) — extracts only the baseURL ─────────────
_P_AXIOS_BASE = re.compile(
    r"""axios\.create\s*\(\s*\{[^}]*baseURL\s*[:=]\s*[`'"]([/a-zA-Z0-9/_\-{}]+)[`'"]"""
)

# ── XMLHttpRequest.open("METHOD", "/api/...") ───────────────────────────────
_P_XHR = re.compile(
    r"""\.open\s*\(\s*[`'"][A-Z]+[`'"]\s*,\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)

# ── jQuery: $.ajax / $.get / $.post / $.getJSON ──────────────────────────────
_P_JQUERY_SHORT = re.compile(
    r"""\$\.(?:get|post|getJSON|getScript)\s*\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+)[`'"]"""
)
_P_JQUERY_AJAX = re.compile(
    r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+)[`'"]"""
)

# ── WebSocket ────────────────────────────────────────────────────────────────
_P_WEBSOCKET = re.compile(
    r"""new\s+WebSocket\s*\(\s*[`'"](wss?://[a-zA-Z0-9/_\-{}$.?&=:@]+)[`'"]"""
)

# ── Config objects: url / path / endpoint / href / apiUrl ───────────────────
_P_CONFIG = re.compile(
    r"""(?:url|path|endpoint|href|baseURL|BASE_URL|apiUrl|API_URL)\s*[:=]\s*[`'"]([/a-zA-Z0-9/_\-{}$.?&=]+)[`'"]"""
)

# ── Standalone API-looking strings ──────────────────────────────────────────
_P_STANDALONE = re.compile(
    r"""[`'"](/(?:api|v[0-9]+|rest|graphql|rpc|gql)/[a-zA-Z0-9/_\-{}$.?&=]+)[`'"]"""
)

_ALL_PATTERNS = [
    _P_FETCH,
    _P_AXIOS_DIRECT,
    _P_AXIOS_BASE,
    _P_XHR,
    _P_JQUERY_SHORT,
    _P_JQUERY_AJAX,
    _P_CONFIG,
    _P_STANDALONE,
]

_WS_PATTERNS = [_P_WEBSOCKET]


class JSExtractor:
    """Extrait les endpoints API depuis le source JavaScript."""

    def extract_endpoints(self, js_source: str, base_url: str) -> list[str]:
        """
        Retourne une liste d'URLs absolues extraites du JS.
        Template literals `${id}` normalisés → `{param}`.
        """
        paths: set[str] = set()

        for pattern in _ALL_PATTERNS:
            for m in pattern.finditer(js_source):
                path = _TEMPLATE_VAR.sub("{param}", m.group(1))
                if _is_valid_path(path):
                    paths.add(path)

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = sorted(f"{base}{p}" for p in paths)

        # WebSockets retournés tels quels (URLs absolues)
        for pattern in _WS_PATTERNS:
            for m in pattern.finditer(js_source):
                url = m.group(1)
                if url not in endpoints:
                    endpoints.append(url)

        return endpoints


def _is_valid_path(path: str) -> bool:
    if len(path) <= 3:
        return False
    if path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".map", ".svg", ".ttf")):
        return False
    if path.count("/") > 8:
        return False
    return True
