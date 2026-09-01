# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ProxyCapture: capture passive du trafic HTTP/HTTPS via proxy MITM.

Démarre un proxy mitmproxy sur un port local. Tout trafic intercepté
est normalisé en RawObservation et émis sur le bus.

Usage :
    capture = ProxyCapture(bus, scope_guard, session_id, port=8080)
    await capture.start()          # bloque jusqu'à capture.stop()
    # ou
    task = asyncio.create_task(capture.start())
    # ... l'utilisateur navigue ...
    await capture.stop()
"""
from __future__ import annotations

import asyncio
import re as _re

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import CREDENTIALS_CAPTURED, OBSERVATION_RAW
from hdwp.core.context.scope_guard import ScopeGuard, ScopeVerdict
from hdwp.core.model.schemas import ObservationType, RawObservation
from hdwp.core.observation.normalizer import normalize_request, normalize_response

log = structlog.get_logger()

# ── Credential auto-capture ───────────────────────────────────────────────

_AUTH_BODY_KEYS = frozenset({
    "token", "access_token", "id_token", "auth_token", "jwt",
    "bearer", "sessionToken", "session_token", "authToken",
})
_SESSION_COOKIE_RE = _re.compile(
    r"(?:session|auth|token|jwt|sid)[_\-]?(?:id|token)?=([^;,\s]+)", _re.IGNORECASE
)


def _extract_auth_token(
    resp_body: object, headers: dict[str, str], seen_tokens: set[str]
) -> tuple[str, str] | None:
    """
    Detect an auth token in a proxy response.
    Deduplicates by value so the same token is never emitted twice within a session.
    Priority: JSON body > Set-Cookie header.
    """
    if isinstance(resp_body, dict):
        for key in _AUTH_BODY_KEYS:
            value = resp_body.get(key)
            if isinstance(value, str) and len(value) > 10 and value not in seen_tokens:
                seen_tokens.add(value)
                return ("bearer", value)

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        m = _SESSION_COOKIE_RE.search(set_cookie)
        if m:
            val = m.group(1)
            if val not in seen_tokens:
                seen_tokens.add(val)
                return ("cookie", val)

    return None


_MITMPROXY_AVAILABLE = False
try:
    import mitmproxy  # noqa: F401
    _MITMPROXY_AVAILABLE = True
except ImportError:
    pass


class ProxyCapture:
    """
    Capture passive via proxy MITM (mitmproxy requis : pip install hdwp[proxy]).

    En mode passif, l'utilisateur configure son navigateur pour utiliser
    ce proxy. Tout trafic dans le scope est normalisé et émis sur le bus.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        scope_guard: ScopeGuard,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        role_name: str = "anonymous",
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._session_id = session_id
        self._host = host
        self._port = port
        self._role_name = role_name
        self._running = False
        self._master: object | None = None
        self._seen_tokens_local: set[str] = set()

    async def start(self) -> None:
        """Démarre le proxy. Bloque jusqu'à stop()."""
        if not _MITMPROXY_AVAILABLE:
            raise RuntimeError(
                "mitmproxy n'est pas installé. "
                "Installer avec : pip install hdwp[proxy]"
            )
        self._running = True
        log.info("proxy.starting", host=self._host, port=self._port)

        from mitmproxy.options import Options  # type: ignore[import-not-found]
        from mitmproxy.tools.dump import DumpMaster  # type: ignore[import-not-found]

        opts = Options(listen_host=self._host, listen_port=self._port)
        self._master = DumpMaster(opts)
        addon = _HDWPAddon(self._bus, self._scope_guard, self._session_id, self._role_name, self._seen_tokens_local)
        self._master.addons.add(addon)  # type: ignore[attr-defined]

        try:
            await self._master.run()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log.debug("proxy.run_ended", reason=str(exc) or "shutdown")
        finally:
            self._running = False
            self._master = None
            log.info("proxy.stopped")

    async def stop(self) -> None:
        """Arrête le proxy."""
        self._running = False
        if self._master is not None:
            try:
                await self._master.shutdown()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass

    @property
    def running(self) -> bool:
        return self._running

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"


class _HDWPAddon:
    """Addon mitmproxy qui intercepte et émet les observations sur le bus."""

    def __init__(
        self,
        bus: AsyncEventBus,
        scope_guard: ScopeGuard,
        session_id: str,
        role_name: str,
        seen_tokens: set[str],
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._session_id = session_id
        self._role_name = role_name
        self._seen_tokens = seen_tokens
        self._loop = asyncio.get_running_loop()
        self._capture_count = 0

    def response(self, flow: object) -> None:  # type: ignore[override]
        """Appelé par mitmproxy après réception de la réponse."""
        from datetime import UTC, datetime

        req = flow.request  # type: ignore[attr-defined]
        resp = flow.response  # type: ignore[attr-defined]

        url = req.pretty_url

        # ── Token capture (independent of scope) ──────────────────────────
        # Auth tokens from login responses must be captured even if the
        # login endpoint is excluded from the pentest scope.
        try:
            import json as _json
            resp_json = _json.loads(resp.content)
        except Exception:  # noqa: BLE001
            resp_json = None

        token_info = _extract_auth_token(resp_json, dict(resp.headers), self._seen_tokens)
        if token_info:
            self._capture_count += 1
            asyncio.run_coroutine_threadsafe(
                self._bus.emit(
                    CREDENTIALS_CAPTURED,
                    {
                        "token_type": token_info[0],
                        "token_value": token_info[1],
                        "role_name": f"captured_{self._capture_count}",
                        "source_url": url,
                    },
                    source="proxy_capture",
                ),
                self._loop,
            )
            log.info(
                "proxy.credential_captured",
                role=f"captured_{self._capture_count}",
                token_type=token_info[0],
                url=url,
            )

        # ── Normal scope-filtered observation ─────────────────────────────
        verdict = self._scope_guard.check(url, req.method)
        if verdict != ScopeVerdict.ALLOWED:
            return

        norm_req = normalize_request(
            method=req.method,
            url=url,
            headers=dict(req.headers),
            body=req.content.decode("utf-8", errors="replace") if req.content else None,
        )
        norm_resp = normalize_response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content.decode("utf-8", errors="replace") if resp.content else None,
            timing_ms=0.0,
        )

        obs = RawObservation(
            timestamp=datetime.now(UTC).isoformat(),
            source="passive",
            type=ObservationType.HTTP,
            request=norm_req,
            response=norm_resp,
            session_id=self._session_id,
            tags=[f"role:{self._role_name}", "source:proxy"],
        )

        asyncio.run_coroutine_threadsafe(
            self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="proxy_capture"),
            self._loop,
        )
        log.debug("proxy.observation", url=url, status=resp.status_code)
