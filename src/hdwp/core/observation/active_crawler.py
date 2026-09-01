# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import base64
import time
from collections import deque
from datetime import UTC, datetime
from html.parser import HTMLParser
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

log = structlog.get_logger()


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
            # Le token est pré-acquis par HDWPEngine.create() et stocké dans cred.token
            return {"Authorization": f"Bearer {cred.token}"} if cred.token else {}
    return {}


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and attr_dict.get("href"):
            self.links.append(attr_dict["href"])  # type: ignore[arg-type]
        elif tag == "form" and attr_dict.get("action"):
            self.links.append(attr_dict["action"])  # type: ignore[arg-type]
        elif tag == "script":
            src = attr_dict.get("src")
            if src and not src.startswith(("data:", "javascript:")):
                self.scripts.append(src)  # type: ignore[arg-type]


def extract_links(html: str, base_url: str) -> list[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    resolved: list[str] = []
    for link in parser.links:
        if link.startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        absolute = urljoin(base_url, link)
        parsed = urlparse(absolute)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        resolved.append(clean)
    return resolved


def extract_script_urls(html: str, page_url: str) -> list[str]:
    """Extrait les URLs absolues des balises <script src='...'> depuis le HTML."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    return [urljoin(page_url, src) for src in parser.scripts]


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
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._rate_limiter = rate_limiter
        self._roles = roles
        self._session_id = session_id
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._inspector = HeaderInspector()

    async def crawl(self, seed_url: str) -> None:
        for role in self._roles:
            await self._crawl_as_role(seed_url, role)

    async def _crawl_as_role(self, seed_url: str, role: RoleConfig) -> None:
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        queue.append((seed_url, 0))
        pages_visited = 0
        auth_headers = _build_auth_headers(role.credentials)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(15.0),
            headers=auth_headers,
        ) as client:
            while queue and pages_visited < self._max_pages:
                url, depth = queue.popleft()
                if url in visited:
                    continue
                if depth > self._max_depth:
                    continue

                verdict = self._scope_guard.check(url, "GET")
                if verdict != ScopeVerdict.ALLOWED:
                    continue

                visited.add(url)
                await self._rate_limiter.acquire()

                start = time.monotonic()
                try:
                    resp = await client.get(url)
                except httpx.HTTPError as exc:
                    log.warning("crawl.request_failed", url=url, error=str(exc))
                    continue
                elapsed_ms = (time.monotonic() - start) * 1000

                norm_req = normalize_request(
                    method="GET",
                    url=url,
                    headers=dict(resp.request.headers),
                )
                norm_resp = normalize_response(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    timing_ms=elapsed_ms,
                )

                tags = self._inspector.inspect(norm_resp)
                tags.append(f"role:{role.name}")

                obs = RawObservation(
                    timestamp=datetime.now(UTC).isoformat(),
                    source="active",
                    type=ObservationType.HTTP,
                    request=norm_req,
                    response=norm_resp,
                    session_id=self._session_id,
                    tags=tags,
                )

                await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="active_crawler")
                pages_visited += 1

                content_type = resp.headers.get("content-type", "")
                if "text/html" in content_type:
                    links = extract_links(resp.text, url)
                    for link in links:
                        if link not in visited:
                            queue.append((link, depth + 1))

                    # Télécharger et analyser les scripts JS pour découvrir des API endpoints
                    if depth < 2:
                        from hdwp.core.observation.js_extractor import JSExtractor
                        js_extractor = JSExtractor()
                        for script_url in extract_script_urls(resp.text, url):
                            scope_v = self._scope_guard.check(script_url, "GET")
                            if scope_v != ScopeVerdict.ALLOWED or script_url in visited:
                                continue
                            visited.add(script_url)
                            try:
                                await self._rate_limiter.acquire()
                                js_resp = await client.get(script_url)
                                js_ct = js_resp.headers.get("content-type", "")
                                if "javascript" in js_ct or script_url.endswith(".js"):
                                    api_urls = js_extractor.extract_endpoints(js_resp.text, url)
                                    for api_url in api_urls:
                                        if api_url not in visited:
                                            queue.append((api_url, depth + 1))
                            except Exception:  # noqa: BLE001, S110
                                pass

        log.info(
            "crawl.complete",
            role=role.name,
            pages_visited=pages_visited,
            urls_found=len(visited),
        )
