# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import base64
import json
import re
import time
from collections import deque
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
from hdwp.core.context.scope_guard import ScopeGuard, ScopeVerdict
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.model.schemas import ObservationType, RawObservation
from hdwp.core.observation.header_inspector import HeaderInspector
from hdwp.core.observation.normalizer import normalize_request, normalize_response

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol

log = structlog.get_logger()

# Regex pour détecter les champs URL dans les réponses JSON (HATEOAS)
_JSON_URL_KEYS = re.compile(r'"(?:href|url|uri|_url|link|location|next|prev|self)":\s*"(/[^"]+)"', re.IGNORECASE)

# Regex pour les Link headers RFC 5988 : <https://example.com/api/next>; rel="next"
_LINK_HEADER = re.compile(r'<([^>]+)>')

# Champs data-* qui contiennent des URLs/endpoints
_DATA_URL_ATTRS = {"data-url", "data-href", "data-action", "data-api", "data-api-url", "data-endpoint", "data-src"}

# Valeurs synthétiques par type d'input pour les soumissions de formulaires
_INPUT_DEFAULTS: dict[str, str] = {
    "email": "test@hdwp.local",
    "password": "Test@1234!",
    "number": "1",
    "tel": "0600000000",
    "date": "2026-01-01",
    "url": "https://test.local",
    "text": "test",
    "search": "test",
    "checkbox": "on",
    "radio": "1",
}


def _build_auth_headers(cred: CredentialConfig | None) -> dict[str, str]:
    if cred is None:
        return {}
    match cred.type:
        case "bearer":
            return {"Authorization": f"Bearer {cred.token}"} if cred.token else {}
        case "basic":
            if cred.username and cred.password:
                encoded = base64.b64encode(
                    f"{cred.username}:{cred.password}".encode()
                ).decode()
                return {"Authorization": f"Basic {encoded}"}
            return {}
        case "api_key":
            name = cred.header_name or "X-Api-Key"
            value = cred.header_value or cred.token or ""
            return {name: value} if value else {}
        case "cookie":
            return {"Cookie": cred.token} if cred.token else {}
        case "oauth2_password" | "oauth2_client_credentials":
            return {"Authorization": f"Bearer {cred.token}"} if cred.token else {}
    return {}


class _LinkExtractor(HTMLParser):
    """Parse HTML et extrait : liens, actions form, scripts externes, scripts inline, data-* attrs."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []   # (url, method)
        self.scripts_src: list[str] = []          # URLs de scripts externes
        self.scripts_inline: list[str] = []       # contenu des scripts inline
        self.form_submissions: list[tuple[str, str, dict[str, str]]] = []  # (action, method, fields)
        self._in_inline_script = False
        self._inline_buf: list[str] = []
        self._in_form = False
        self._current_form_action = ""
        self._current_form_method = "GET"
        self._current_form_inputs: dict[str, str] = {}
        self._pending_select: str = ""
        self._textarea_name: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "a":
            href = attr_dict.get("href")
            if href:
                self.links.append((href, "GET"))
        elif tag == "form":
            action = attr_dict.get("action") or ""
            method = (attr_dict.get("method") or "GET").upper()
            if action:
                self.links.append((action, method))
            # Track form for input collection
            self._in_form = True
            self._current_form_action = action
            self._current_form_method = method
            self._current_form_inputs = {}
        elif tag == "input" and self._in_form:
            name = attr_dict.get("name", "")
            if name:
                input_type = (attr_dict.get("type") or "text").lower()
                value = attr_dict.get("value") or ""
                if input_type == "hidden":
                    self._current_form_inputs[name] = value  # garder la valeur originale
                elif input_type not in ("submit", "reset", "button", "image", "file"):
                    self._current_form_inputs[name] = _INPUT_DEFAULTS.get(input_type, "test")
        elif tag == "textarea" and self._in_form:
            name = attr_dict.get("name", "")
            if name:
                self._textarea_name = name
                self._current_form_inputs[name] = "test_content"  # valeur par défaut
        elif tag == "select" and self._in_form:
            name = attr_dict.get("name", "")
            if name:
                self._pending_select = name
        elif tag == "option" and self._pending_select:
            val = attr_dict.get("value", "option1")
            # Prendre la valeur marquée selected en priorité, sinon la première
            if self._pending_select not in self._current_form_inputs or "selected" in attr_dict:
                self._current_form_inputs[self._pending_select] = val
        elif tag == "button":
            fa = attr_dict.get("formaction")
            if fa:
                method = (attr_dict.get("formmethod") or "POST").upper()
                self.links.append((fa, method))
        elif tag == "link":
            # <link rel="prefetch|preload|canonical" href="...">
            rel = attr_dict.get("rel", "")
            href = attr_dict.get("href")
            if href and rel in ("prefetch", "preload", "canonical", "alternate"):
                self.links.append((href, "GET"))
        elif tag == "script":
            src = attr_dict.get("src")
            if src and not src.startswith(("data:", "javascript:")):
                self.scripts_src.append(src)
            else:
                self._in_inline_script = True
                self._inline_buf = []
        # data-* attributes
        for key, val in attrs:
            if key in _DATA_URL_ATTRS and val and val.startswith("/"):
                self.links.append((val, "GET"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            if self._current_form_action:
                self.form_submissions.append((
                    self._current_form_action,
                    self._current_form_method,
                    dict(self._current_form_inputs),
                ))
            self._in_form = False
            self._current_form_inputs = {}
            self._pending_select = ""
            self._textarea_name = ""
        elif tag == "select":
            self._pending_select = ""
        elif tag == "textarea":
            self._textarea_name = ""
        elif tag == "script" and self._in_inline_script:
            self._in_inline_script = False
            self.scripts_inline.append("".join(self._inline_buf))
            self._inline_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_inline_script:
            self._inline_buf.append(data)
        elif self._textarea_name and self._in_form and data.strip():
            # Contenu réel d'un textarea (entre les balises ouvrante et fermante)
            self._current_form_inputs[self._textarea_name] = data.strip()


def extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Retourne liste de (url_absolue, méthode)."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    resolved: list[tuple[str, str]] = []
    for link, method in parser.links:
        if link.startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        absolute = urljoin(base_url, link)
        parsed = urlparse(absolute)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        resolved.append((clean, method))
    return resolved


def extract_script_urls(html: str, page_url: str) -> list[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    return [urljoin(page_url, src) for src in parser.scripts_src]


def extract_inline_scripts(html: str) -> list[str]:
    """Retourne le contenu de tous les blocs <script> inline."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    return parser.scripts_inline


def extract_json_urls(body: str, base_url: str) -> list[str]:
    """Extrait les URLs de champs HATEOAS (href, url, uri, next, prev…) dans un corps JSON."""
    urls = []
    for m in _JSON_URL_KEYS.finditer(body):
        path = m.group(1)
        if path.startswith("/"):
            parsed = urlparse(base_url)
            urls.append(f"{parsed.scheme}://{parsed.netloc}{path}")
    return urls


def extract_link_header_urls(link_header: str, base_url: str) -> list[str]:
    """Parse le header Link: RFC 5988 et retourne les URLs absolues."""
    urls = []
    for m in _LINK_HEADER.finditer(link_header):
        url = m.group(1)
        if url.startswith("/"):
            parsed = urlparse(base_url)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"
        if url.startswith("http"):
            urls.append(url)
    return urls


def extract_form_submissions(html: str, base_url: str) -> list[tuple[str, str, dict[str, str]]]:
    """Retourne (url_absolue, méthode, champs) pour chaque formulaire avec action."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    result: list[tuple[str, str, dict[str, str]]] = []
    for action, method, fields in parser.form_submissions:
        if action.startswith(("javascript:", "data:", "#", "mailto:")):
            continue
        absolute = urljoin(base_url, action)
        parsed = urlparse(absolute)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        result.append((clean, method, fields))
    return result


class ActiveCrawler:
    def __init__(
        self,
        bus: AsyncEventBus,
        scope_guard: ScopeGuard,
        rate_limiter: TokenBucket,
        roles: list[RoleConfig],
        session_id: str,
        max_depth: int = 3,
        max_pages: int = 100,
        llm_layer: LLMLayerProtocol | None = None,
        proxy_url: str | None = None,
        emit_observations: bool = True,
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._rate_limiter = rate_limiter
        self._roles = roles
        self._session_id = session_id
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._inspector = HeaderInspector()
        self._llm_layer = llm_layer
        self._proxy_url = proxy_url
        self._emit_observations = emit_observations
        self._script_urls: set[str] = set()
        self._script_contents: dict[str, str] = {}
        self._script_pages: dict[str, list[str]] = {}
        self._form_bodies: dict[str, dict[str, str]] = {}  # url → form fields
        self._options_probed: set[str] = set()   # chemins déjà sondés par OPTIONS
        self._methods_probed: set[str] = set()   # chemins déjà sondés pour multi-méthodes

    @staticmethod
    def _normalize_path(url: str) -> str:
        from hdwp.core.model.url_utils import normalize_url_path
        return normalize_url_path(url)

    @property
    def script_urls(self) -> frozenset[str]:
        return frozenset(self._script_urls)

    @property
    def script_contents(self) -> dict[str, str]:
        return dict(self._script_contents)

    @property
    def script_pages(self) -> dict[str, list[str]]:
        return dict(self._script_pages)

    async def crawl(self, seed_url: str) -> None:
        parsed = urlparse(seed_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        for role in self._roles:
            from hdwp.core.http_client import build_client
            # proxy_url = hdwp_proxy MITM (pour interception) — prime sur Tor.
            # Si aucun proxy MITM, build_client() injecte Tor automatiquement.
            async with build_client(
                timeout=15.0,
                proxy_url=self._proxy_url,  # None → Tor via module global
            ) as client:
                client.headers.update(_build_auth_headers(role.credentials) or {})
                # Consulter robots.txt et sitemap avant le BFS
                extra_seeds = await self._seed_from_robots_sitemap(client, base_origin, seed_url)
                await self._crawl_as_role(client, seed_url, role, base_origin, extra_seeds)

    async def _seed_from_robots_sitemap(
        self,
        client: httpx.AsyncClient,
        base_origin: str,
        seed_url: str,
    ) -> list[str]:
        """Extrait des URLs depuis robots.txt et sitemap.xml."""
        seeds: list[str] = []
        await self._rate_limiter.acquire()

        for path in ["/robots.txt", "/sitemap.xml"]:
            url = base_origin + path
            try:
                await self._rate_limiter.acquire()
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                text = resp.text
                if path == "/robots.txt":
                    # Extraire les Disallow / Allow / Sitemap lines
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:")):
                            part = line.split(":", 1)[1].strip()
                            if part and part not in ("*", "/"):
                                seeds.append(urljoin(seed_url, part))
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if sitemap_url.startswith("http"):
                                seeds.append(sitemap_url)
                elif path == "/sitemap.xml":
                    # Extraire les <loc> depuis le XML
                    for m in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", text):
                        seeds.append(m.group(1).strip())
            except Exception:  # noqa: BLE001
                pass

        log.debug("crawler.seeds_from_robots", count=len(seeds))
        return seeds

    async def _crawl_as_role(
        self,
        client: httpx.AsyncClient,
        seed_url: str,
        role: RoleConfig,
        base_origin: str,
        extra_seeds: list[str],
    ) -> None:
        visited: set[str] = set()
        queue: deque[tuple[str, int, str, str]] = deque()  # (url, depth, method, parent_pattern)
        queue.append((seed_url, 0, "GET", ""))
        for s in extra_seeds:
            queue.append((s, 1, "GET", ""))

        pages_visited = 0
        js_extractor_cls = None

        while queue and pages_visited < self._max_pages:
            url, depth, method, parent_pattern = queue.popleft()
            if url in visited:
                continue
            if depth > self._max_depth:
                continue

            # Scope check — GET et POST/PUT/DELETE ont des règles distinctes
            verdict = self._scope_guard.check(url, method)
            if verdict != ScopeVerdict.ALLOWED:
                continue

            visited.add(url)
            await self._rate_limiter.acquire()

            start = time.monotonic()
            form_body = self._form_bodies.get(url) if method != "GET" else None
            try:
                if method == "GET":
                    resp = await client.get(url)
                elif form_body:
                    resp = await client.request(method, url, data=form_body, timeout=10.0)
                else:
                    resp = await client.request(method, url, timeout=10.0)
            except httpx.HTTPError as exc:
                log.warning("crawl.request_failed", url=url, method=method, error=str(exc))
                continue
            elapsed_ms = (time.monotonic() - start) * 1000

            norm_req = normalize_request(
                method=method,
                url=url,
                headers=dict(resp.request.headers),
                body=form_body,
            )
            norm_resp = normalize_response(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                timing_ms=elapsed_ms,
            )

            tags = self._inspector.inspect(norm_resp, request_url=url)
            tags.append(f"role:{role.name}")
            if parent_pattern and parent_pattern != self._normalize_path(url):
                tags.append(f"from:{parent_pattern}")

            obs = RawObservation(
                timestamp=datetime.now(UTC).isoformat(),
                source="active",
                type=ObservationType.HTTP,
                request=norm_req,
                response=norm_resp,
                session_id=self._session_id,
                tags=tags,
            )
            if self._emit_observations:
                await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="active_crawler")
            pages_visited += 1

            # Sonder OPTIONS pour découvrir les méthodes autorisées et headers CORS
            # Sonder POST/PUT/PATCH pour alimenter le corpus avec des méthodes non-GET
            if resp.status_code < 400 and method == "GET":
                await self._probe_options(client, url)
                await self._probe_methods(client, url, role.name)

            content_type = resp.headers.get("content-type", "")

            # ── Link header (RFC 5988) ────────────────────────────────────
            link_hdr = resp.headers.get("link", "")
            if link_hdr:
                for link_url in extract_link_header_urls(link_hdr, url):
                    if link_url not in visited:
                        queue.append((link_url, depth + 1, "GET", self._normalize_path(url)))

            if "text/html" in content_type:
                # ── Liens HTML + forms + data-* ───────────────────────────
                current_pattern = self._normalize_path(url)
                for link, lmethod in extract_links(resp.text, url):
                    if link not in visited:
                        queue.append((link, depth + 1, lmethod, current_pattern))

                # ── Soumissions de formulaires avec corps réalistes ────────
                for form_url, form_method, form_fields in extract_form_submissions(resp.text, url):
                    if form_url not in visited and self._scope_guard.check(form_url, form_method) == ScopeVerdict.ALLOWED:
                        queue.append((form_url, depth + 1, form_method, current_pattern))
                        if form_fields:
                            self._form_bodies[form_url] = form_fields

                # ── Scripts externes ─────────────────────────────────────
                if js_extractor_cls is None:
                    from hdwp.core.observation.js_extractor import JSExtractor
                    js_extractor_cls = JSExtractor

                for script_url in extract_script_urls(resp.text, url):
                    self._script_pages.setdefault(script_url, []).append(url)
                    await self._process_js(
                        client, script_url, url, depth, visited, queue,
                        js_extractor_cls, allow_external=True,
                    )

                # ── Scripts inline ────────────────────────────────────────
                if js_extractor_cls is None:
                    from hdwp.core.observation.js_extractor import JSExtractor
                    js_extractor_cls = JSExtractor
                extractor = js_extractor_cls()
                for inline_src in extract_inline_scripts(resp.text):
                    if inline_src.strip():
                        api_endpoints = extractor.extract_endpoints(inline_src, url)
                        for api_url, js_method in api_endpoints:
                            if api_url not in visited:
                                # "WS" (WebSocket) ne passe pas dans la queue HTTP
                                queue_method = js_method if js_method != "WS" else "GET"
                                queue.append((api_url, depth + 1, queue_method, current_pattern))
                        if not api_endpoints and self._llm_layer is not None:
                            await self._llm_enrich(inline_src, url, visited, queue)

            elif "application/json" in content_type or "text/json" in content_type:
                # ── Corps JSON : extraire les liens HATEOAS ────────────────
                for json_url in extract_json_urls(resp.text, url):
                    if json_url not in visited:
                        queue.append((json_url, depth + 1, "GET", self._normalize_path(url)))

            elif "javascript" in content_type or url.endswith(".js"):
                # ── Fichier JS direct ─────────────────────────────────────
                if js_extractor_cls is None:
                    from hdwp.core.observation.js_extractor import JSExtractor
                    js_extractor_cls = JSExtractor
                extractor = js_extractor_cls()
                api_endpoints = extractor.extract_endpoints(resp.text, url)
                for api_url, js_method in api_endpoints:
                    if api_url not in visited:
                        queue_method = js_method if js_method != "WS" else "GET"
                        queue.append((api_url, depth + 1, queue_method, ""))

        log.info(
            "crawl.complete",
            role=role.name,
            pages_visited=pages_visited,
            urls_found=len(visited),
        )

    async def _probe_options(self, client: httpx.AsyncClient, url: str) -> None:
        """Émet une requête OPTIONS pour découvrir Allow/CORS — une seule fois par chemin normalisé."""
        key = self._normalize_path(url)
        if key in self._options_probed:
            return
        self._options_probed.add(key)
        try:
            r = await client.request("OPTIONS", url, timeout=5.0)
            allow_hdr = r.headers.get("allow", "")
            acao_hdr = r.headers.get("access-control-allow-origin", "")
            if not allow_hdr and not acao_hdr:
                return
            norm_req = normalize_request(method="OPTIONS", url=url, headers={}, body=None)
            norm_resp = normalize_response(
                status_code=r.status_code,
                headers=dict(r.headers),
                body=None,
                timing_ms=0.0,
            )
            obs = RawObservation(
                timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                source="active",
                type=ObservationType.HTTP,
                request=norm_req,
                response=norm_resp,
                session_id=self._session_id,
                tags=["options_probe", f"allow:{allow_hdr}" if allow_hdr else "cors_discovered"],
            )
            if self._emit_observations:
                await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="active_crawler")
        except Exception:  # noqa: BLE001
            pass

    async def _probe_methods(self, client: httpx.AsyncClient, url: str, role_name: str) -> None:
        """Sonde POST/PUT/PATCH sur chaque endpoint GET découvert.

        Alimente le corpus avec des observations de méthodes non-GET,
        ce qui permet à l'expérimentation de tester ces méthodes
        sans spec OpenAPI ni proxy capturant du trafic réel.

        Règles :
        - DELETE exclu (destructif)
        - 405 Method Not Allowed → méthode non supportée, skip
        - 2xx / 4xx (sauf 405) → méthode acceptée (même si requiert un corps),
          l'observation est émise et alimente le corpus
        """
        key = self._normalize_path(url)
        if key in self._methods_probed:
            return
        self._methods_probed.add(key)

        for method in ("POST", "PUT", "PATCH"):
            try:
                r = await client.request(
                    method, url,
                    json={},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0,
                )
                # 405 = méthode explicitement refusée → inutile à tester
                if r.status_code == 405:
                    continue
                # Toute autre réponse (200/201/400/401/403/422) = méthode connue du serveur
                norm_req = normalize_request(
                    method=method, url=url,
                    headers={"Content-Type": "application/json"},
                    body={},
                )
                norm_resp = normalize_response(
                    status_code=r.status_code,
                    headers=dict(r.headers),
                    body=r.text,
                    timing_ms=0.0,
                )
                obs = RawObservation(
                    timestamp=datetime.now(UTC).isoformat(),
                    source="active",
                    type=ObservationType.HTTP,
                    request=norm_req,
                    response=norm_resp,
                    session_id=self._session_id,
                    tags=[f"role:{role_name}", "source:method_probe"],
                )
                if self._emit_observations:
                    await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="active_crawler")
            except Exception:  # noqa: BLE001
                pass

    async def _process_js(
        self,
        client: httpx.AsyncClient,
        script_url: str,
        page_url: str,
        depth: int,
        visited: set[str],
        queue: deque,
        extractor_cls,
        allow_external: bool = False,
    ) -> None:
        """Télécharge et analyse un fichier JS — ignore le scope pour les fichiers externes (CDN)."""
        if script_url in visited:
            return

        # Enregistrer l'URL dès qu'on la voit (pour la détection de version CDN)
        self._script_urls.add(script_url)

        # Pour les fichiers JS externes (CDN), on les analyse sans les ajouter au crawl de liens
        is_in_scope = self._scope_guard.check(script_url, "GET") == ScopeVerdict.ALLOWED
        if not is_in_scope and not allow_external:
            return

        visited.add(script_url)
        try:
            await self._rate_limiter.acquire()
            js_resp = await client.get(script_url, timeout=10.0)
            js_ct = js_resp.headers.get("content-type", "")
            if "javascript" not in js_ct and not script_url.endswith((".js", ".mjs", ".cjs")):
                return

            # Stocker le contenu pour la détection de version (plafonné à 50KB)
            if js_resp.text:
                self._script_contents[script_url] = js_resp.text[:50000]

            extractor = extractor_cls()
            # Pour JS externe (CDN), résoudre les chemins relatifs par rapport à la page appelante
            resolve_base = page_url if not is_in_scope else script_url
            api_endpoints = extractor.extract_endpoints(js_resp.text, resolve_base)

            for api_url, js_method in api_endpoints:
                if api_url not in visited:
                    # N'ajouter à la file que les URLs dans le scope
                    queue_method = js_method if js_method != "WS" else "GET"
                    if self._scope_guard.check(api_url, queue_method) == ScopeVerdict.ALLOWED:
                        queue.append((api_url, depth + 1, queue_method, ""))

            if not api_endpoints and self._llm_layer is not None:
                await self._llm_enrich(js_resp.text, page_url, visited, queue)

        except Exception:  # noqa: BLE001
            pass

    async def _llm_enrich(
        self,
        source: str,
        base_url: str,
        visited: set[str],
        queue: deque,
    ) -> None:
        if self._llm_layer is None:
            return
        try:
            llm_paths = await self._llm_layer.interpret_js(source)
            for path in llm_paths:
                abs_url = urljoin(base_url, path) if path.startswith("/") else path
                if self._scope_guard.check(abs_url, "GET") == ScopeVerdict.ALLOWED:
                    if abs_url not in visited:
                        queue.append((abs_url, 2, "GET", ""))
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.interpret_js_error", error=str(exc))
