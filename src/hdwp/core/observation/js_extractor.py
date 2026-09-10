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

# ── fetch() — capture optionnelle de la méthode dans le 2e argument ──────────
_P_FETCH = re.compile(
    r"""(?:window\.)?fetch\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)
# Variante qui tente de capturer method: 'POST' dans les options fetch
_P_FETCH_METHOD = re.compile(
    r"""(?:window\.)?fetch\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
    r"""(?:[^;{]{0,100}\{[^}]{0,200}method\s*:\s*[`'"]([A-Z]+)[`'"])?""",
    re.DOTALL,
)

# ── axios direct calls: axios.post('/api/...') — capture la méthode ──────────
_P_AXIOS_DIRECT = re.compile(
    r"""axios\.[a-z]+\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)
# Variante avec capture de méthode depuis le nom de fonction
_P_AXIOS_WITH_METHOD = re.compile(
    r"""axios\.([a-z]+)\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)

# ── axios.create({ baseURL: '/api' }) — extracts only the baseURL ─────────────
_P_AXIOS_BASE = re.compile(
    r"""axios\.create\s*\(\s*\{[^}]*baseURL\s*[:=]\s*[`'"]([/a-zA-Z0-9/_\-{}]+)[`'"]"""
)

# ── XMLHttpRequest.open("METHOD", "/api/...") — capture la méthode ──────────
_P_XHR = re.compile(
    r"""\.open\s*\(\s*[`'"][A-Z]+[`'"]\s*,\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)
_P_XHR_WITH_METHOD = re.compile(
    r"""\.open\s*\(\s*[`'"]([A-Z]+)[`'"]\s*,\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+(?:\$\{[^}]*\}[a-zA-Z0-9/_\-{}]*)*)[`'"]"""
)

# ── jQuery: $.ajax / $.get / $.post / $.getJSON — capture la méthode ─────────
_P_JQUERY_SHORT = re.compile(
    r"""\$\.(?:get|post|getJSON|getScript)\s*\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+)[`'"]"""
)
_P_JQUERY_WITH_METHOD = re.compile(
    r"""\$\.(get|post|getJSON|getScript)\s*\(\s*[`'"]([/a-zA-Z0-9/_\-{}$\[\].?&=]+)[`'"]"""
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

# Patterns sans capture de méthode (toujours GET par défaut)
_GET_ONLY_PATTERNS = [
    _P_AXIOS_BASE,
    _P_JQUERY_AJAX,
    _P_CONFIG,
    _P_STANDALONE,
]

_WS_PATTERNS = [_P_WEBSOCKET]

# Mapping méthode jQuery depuis nom de fonction
_JQUERY_METHOD_MAP = {"get": "GET", "post": "POST", "getjson": "GET", "getscript": "GET"}
# Méthodes axios valides (le nom de la fonction est la méthode sauf "create"/"all"/"spread")
_AXIOS_VALID_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


class JSExtractor:
    """Extrait les endpoints API depuis le source JavaScript."""

    def extract_endpoints(self, js_source: str, base_url: str) -> list[tuple[str, str]]:
        """
        Retourne une liste de (url_absolue, méthode_HTTP) extraites du JS.
        Template literals `${id}` normalisés → `{param}`.
        Méthodes extraites depuis fetch(options), axios.post(), XHR.open("POST",...), jQuery.post().
        """
        results: dict[str, str] = {}  # url → method (premier trouvé gagne)

        def _add(path: str, method: str = "GET") -> None:
            path = _TEMPLATE_VAR.sub("{param}", path)
            if not _is_valid_path(path):
                return
            parsed = urlparse(base_url)
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            if url not in results:
                results[url] = method.upper()

        # fetch avec capture de méthode
        for m in _P_FETCH_METHOD.finditer(js_source):
            method = m.group(2) if m.lastindex and m.lastindex >= 2 and m.group(2) else "GET"
            _add(m.group(1), method)

        # axios avec méthode depuis nom de fonction
        for m in _P_AXIOS_WITH_METHOD.finditer(js_source):
            fn_name = m.group(1).lower()
            method = fn_name.upper() if fn_name in _AXIOS_VALID_METHODS else "GET"
            _add(m.group(2), method)

        # XHR avec méthode explicite
        for m in _P_XHR_WITH_METHOD.finditer(js_source):
            _add(m.group(2), m.group(1))

        # jQuery avec méthode depuis nom de fonction
        for m in _P_JQUERY_WITH_METHOD.finditer(js_source):
            method = _JQUERY_METHOD_MAP.get(m.group(1).lower(), "GET")
            _add(m.group(2), method)

        # Patterns sans méthode connue → GET
        for pattern in _GET_ONLY_PATTERNS:
            for m in pattern.finditer(js_source):
                _add(m.group(1), "GET")

        endpoints: list[tuple[str, str]] = list(results.items())

        # WebSockets retournés tels quels (URLs absolues) avec méthode "WS"
        for pattern in _WS_PATTERNS:
            for m in pattern.finditer(js_source):
                url = m.group(1)
                if url not in results:
                    endpoints.append((url, "WS"))

        return endpoints


def _is_valid_path(path: str) -> bool:
    if len(path) <= 3:
        return False
    if "*" in path:
        return False
    if path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".map", ".svg", ".ttf")):
        return False
    if path.count("/") > 8:
        return False
    return True


# ── DOM Sink Analysis ─────────────────────────────────────────────────────────

from dataclasses import dataclass


@dataclass
class DomSink:
    sink_type: str          # "innerHTML", "eval", "document.write", etc.
    source_hint: str | None # variable ou input apparent dans le contexte
    snippet: str            # 80 chars de contexte

_DOM_SINK_PATTERNS: dict[str, re.Pattern] = {
    "innerHTML":        re.compile(r'\.innerHTML\s*[+]?=\s*(.{1,80})', re.MULTILINE),
    "outerHTML":        re.compile(r'\.outerHTML\s*=\s*(.{1,80})', re.MULTILINE),
    "document.write":   re.compile(r'document\.write\s*\((.{1,80})\)', re.MULTILINE),
    "document.writeln": re.compile(r'document\.writeln\s*\((.{1,80})\)', re.MULTILINE),
    "eval":             re.compile(r'\beval\s*\((.{1,80})\)', re.MULTILINE),
    "setTimeout_str":   re.compile(r'setTimeout\s*\(\s*["\'](.{1,60})["\']', re.MULTILINE),
    "setInterval_str":  re.compile(r'setInterval\s*\(\s*["\'](.{1,60})["\']', re.MULTILINE),
    "location.href":    re.compile(r'location\.href\s*=\s*(.{1,80})', re.MULTILINE),
    "location.replace": re.compile(r'location\.replace\s*\((.{1,80})\)', re.MULTILINE),
    "location.hash":    re.compile(r'location\.hash', re.MULTILINE),
    "postMessage_listener": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.MULTILINE),
    "jquery.html":      re.compile(r'\$\s*\([^)]{1,60}\)\.html\s*\((.{1,60})\)', re.MULTILINE),
    "jquery.append":    re.compile(r'\$\s*\([^)]{1,60}\)\.(?:append|prepend|after|before)\s*\((.{1,60})\)', re.MULTILINE),
    "insertAdjacentHTML": re.compile(r'insertAdjacentHTML\s*\(\s*["\'][^"\']+["\']\s*,\s*(.{1,80})\)', re.MULTILINE),
}

# Patterns indiquant que le contenu vient d'une source utilisateur contrôlable
_USER_INPUT_SOURCES = re.compile(
    r'location\.(?:hash|search|href|pathname)|'
    r'document\.(?:referrer|URL|documentURI)|'
    r'window\.name|'
    r'(?:get|query)Param|'
    r'(?:url|href|src|data)\s*[=:]\s*(?:req|request|params|query|input)',
    re.IGNORECASE
)


def extract_dom_sinks(js_source: str) -> list[DomSink]:
    """Détecte les sinks DOM dangereux dans un script JavaScript.

    Retourne la liste des sinks trouvés avec leur contexte.
    Les sinks où la source semble contrôlable par l'utilisateur sont prioritaires.
    """
    sinks: list[DomSink] = []
    for sink_type, pattern in _DOM_SINK_PATTERNS.items():
        for m in pattern.finditer(js_source):
            snippet = m.group(0)[:100].replace("\n", " ").strip()
            context = js_source[max(0, m.start() - 200): m.end() + 200]
            source_hint = None
            user_src = _USER_INPUT_SOURCES.search(context)
            if user_src:
                source_hint = user_src.group(0)[:60]
            sinks.append(DomSink(
                sink_type=sink_type,
                source_hint=source_hint,
                snippet=snippet,
            ))
    return sinks
