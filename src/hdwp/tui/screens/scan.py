# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""ScanScreen: ecran principal du scan -- proxy + engine + live events."""
from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import structlog
from textual._work_decorator import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer

from hdwp.tui.messages import (
    BusEvent,
    CredentialCaptured,
    EngineComplete,
    EngineError,
    FindingUpdate,
    ProxyUnavailable,
    StatusUpdate,
)
from hdwp.tui.widgets import EventLogPanel, FindingsTable, StatusPanel

log = structlog.get_logger()

SEV_BARS: ClassVar[dict[str, str]] = {
    "CRITICAL": "[red]####[/red]",
    "HIGH": "[red]###-[/red]",
    "MEDIUM": "[yellow]##--[/yellow]",
    "LOW": "[green]#---[/green]",
    "INFO": "[blue]----[/blue]",
}


class ScanScreen(Screen):
    """Ecran principal du scan."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f", "findings", "Findings", show=True),
        Binding("r", "report", "Report", show=True),
        Binding("p", "plugins", "Plugins", show=True),
        Binding("s", "stop", "Stop", show=True),
        Binding("escape", "pop_screen", "Retour", show=True),
    ]

    def __init__(
        self,
        target_url: str,
        mode: str = "auto",
        context_path: Path | None = None,
        manual_tokens: list[Any] | None = None,
    ) -> None:
        super().__init__()
        self._target_url = target_url
        self._mode = mode
        self._context_path = context_path
        self._manual_tokens = manual_tokens or []
        self._engine: Any = None
        self._proxy_capture: Any = None
        self._bus: Any = None
        self._ctx: Any = None
        self._scope_guard: Any = None
        self._session_id: str = ""
        self._findings: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="scan-panels"):
            with Vertical(id="left-panels"):
                yield StatusPanel(id="status-panel")
            with Vertical(id="right-panels"):
                yield EventLogPanel(id="event-log")
        yield FindingsTable(id="findings-table")
        yield Footer()

    def on_mount(self) -> None:
        from hdwp.core.bus.event_bus import AsyncEventBus
        from hdwp.core.context.loader import ContextLoader
        from hdwp.core.context.scope_guard import ScopeGuard

        self._bus = AsyncEventBus()

        # Charger le contexte
        if self._context_path:
            self._ctx = ContextLoader.load(self._context_path)
        else:
            from hdwp.core.paths import build_context_from_url

            ctx_path = build_context_from_url(self._target_url)
            self._ctx = ContextLoader.load(ctx_path)

        self._scope_guard = ScopeGuard(self._ctx)
        self._session_id = self._ctx.session_id

        # Injecter les tokens manuels dans le contexte si fournis
        if self._manual_tokens:
            self._ctx.config.roles.extend(self._manual_tokens)

        # Bridge bus -> TUI pour le live feed
        self._subscribe_to_bus(self._bus)

        # Mettre a jour le header
        self.app.query_one("#hdwp-header").set_session(self._session_id)

        # Demarrer proxy puis moteur
        if self._mode == "auto":
            self._start_proxy_worker()
        self._start_engine_worker()

    @work(exclusive=False, name="proxy_worker")
    async def _start_proxy_worker(self) -> None:
        """Proxy demarre en parallele, INDEPENDAMMENT du moteur."""
        try:
            from hdwp.core.observation.proxy_capture import ProxyCapture

            self._proxy_capture = ProxyCapture(
                self._bus, self._scope_guard, self._session_id, port=8080
            )
            self.post_message(
                StatusUpdate("proxy", 0.0, "Proxy MITM 127.0.0.1:8080 actif")
            )
            await self._proxy_capture.start()  # bloque jusqu'a stop
        except (RuntimeError, ImportError):
            self._proxy_capture = None
            self.post_message(ProxyUnavailable())

    @work(exclusive=True, name="engine_worker")
    async def _start_engine_worker(self) -> None:
        """Moteur demarre avec le meme bus que le proxy."""
        try:
            from hdwp.core.engine import HDWPEngine

            self._engine = await HDWPEngine.create_from_context(
                self._ctx,
                bus=self._bus,
            )
            status = self.query_one(StatusPanel)
            status.set_target(self._target_url)
            status.update_status("crawl", 0.1, "Crawling...")

            findings = await self._engine.run()
            self.post_message(EngineComplete(len(findings)))
        except (RuntimeError, OSError) as exc:
            self.post_message(EngineError(str(exc)))
        finally:
            if self._engine:
                await self._engine.close()
                self._engine = None
            # Arreter le proxy quand le moteur termine
            if self._proxy_capture:
                await self._proxy_capture.stop()

    def _subscribe_to_bus(self, bus: Any) -> None:
        """Bridge HDWP bus events -> Textual messages."""
        from hdwp.core.bus.events import (
            CREDENTIALS_CAPTURED,
            EXPERIMENT_RESULT,
            FINDING_CONFIRMED,
            HYPOTHESIS_GENERATED,
            OBSERVATION_RAW,
        )

        def _obs(e: Any) -> None:
            url = ""
            if isinstance(e.payload, dict):
                req = e.payload.get("request") or {}
                url = req.get("url", "")[:50] if isinstance(req, dict) else ""
            self.post_message(BusEvent("OBS", {"url": url}))

        def _hyp(e: Any) -> None:
            data = e.payload if isinstance(e.payload, dict) else {}
            self.post_message(
                BusEvent("HYP", {"statement": data.get("statement", "")[:50]})
            )

        def _exp(e: Any) -> None:
            self.post_message(BusEvent("EXP", {}))

        bus.on(OBSERVATION_RAW, _obs)
        bus.on(HYPOTHESIS_GENERATED, _hyp)
        bus.on(EXPERIMENT_RESULT, _exp)
        bus.on(
            FINDING_CONFIRMED,
            lambda e: self.post_message(
                FindingUpdate(e.payload if isinstance(e.payload, dict) else {})
            ),
        )
        bus.on(
            CREDENTIALS_CAPTURED,
            lambda e: self.post_message(
                CredentialCaptured(e.payload if isinstance(e.payload, dict) else {})
            ),
        )

    # -- Message handlers ---------------------------------------------------

    def on_bus_event(self, message: BusEvent) -> None:
        event_log = self.query_one(EventLogPanel)
        if message.event_type == "OBS":
            url = message.payload.get("url", "")
            event_log.add_event("OBS", f"GET {url}" if url else "observation")
        elif message.event_type == "HYP":
            stmt = message.payload.get("statement", "hypothesis generated")
            event_log.add_event("HYP", stmt[:60])
        elif message.event_type == "EXP":
            event_log.add_event("EXP", "executing experiment...")

    def on_finding_update(self, message: FindingUpdate) -> None:
        self.query_one(FindingsTable).add_finding(message.finding_data)
        self._findings.append(message.finding_data)
        fid = message.finding_data.get("id", "?")
        sev = message.finding_data.get("severity", "?")
        conf = f"{message.finding_data.get('confidence', 0):.0%}"
        self.query_one(EventLogPanel).add_event("V", f"{fid} {sev} conf:{conf}")

    def on_credential_captured(self, message: CredentialCaptured) -> None:
        role = message.data.get("role_name", "captured")
        token_type = message.data.get("token_type", "?")
        url = message.data.get("source_url", "")[:35]
        self.query_one(EventLogPanel).add_event(
            "KEY", f"Token capture : {role} ({token_type}) depuis {url}"
        )
        self.notify(
            f"Token capture : {role} ({token_type})",
            title="CREDENTIAL CAPTURED",
            severity="information",
            timeout=3.0,
        )

    def on_engine_complete(self, message: EngineComplete) -> None:
        self.query_one(StatusPanel).update_status(
            "done", 1.0, f"{message.finding_count} finding(s)"
        )
        self.query_one(EventLogPanel).add_event(
            "V", f"Analyse terminee -- {message.finding_count} finding(s) confirmes"
        )

    def on_engine_error(self, message: EngineError) -> None:
        self.query_one(EventLogPanel).add_event("ERR", message.error)
        self.query_one(StatusPanel).update_status("error", 0.0, "Erreur")

    def on_proxy_unavailable(self, message: ProxyUnavailable) -> None:
        """Le proxy n'a pas pu demarrer -- le scan continue sans."""
        status = self.query_one(StatusPanel)
        status.set_proxy_status(active=False)
        self.query_one(EventLogPanel).add_event(
            "ERR", "Proxy indisponible (mitmproxy absent ou port occupe)"
        )
        self.notify(
            "Le scan continue sans proxy. "
            "Installez mitmproxy pour capturer les credentials.",
            title="PROXY OFF",
            severity="warning",
            timeout=5.0,
        )

    def on_status_update(self, message: StatusUpdate) -> None:
        self.query_one(StatusPanel).update_status(
            message.phase, message.progress, message.detail
        )

    # -- Keyboard actions ---------------------------------------------------

    async def action_stop(self) -> None:
        """[S] -- arrete proxy ET moteur."""
        for w in self.workers:
            w.cancel()
        if self._proxy_capture:
            await self._proxy_capture.stop()
            self._proxy_capture = None
        if self._engine:
            await self._engine.close()
            self._engine = None
        self.query_one(EventLogPanel).add_event("ERR", "Scan arrete par l'utilisateur")
        self.query_one(StatusPanel).update_status("error", 0.0, "Arrete")

    def action_findings(self) -> None:
        """[F] -- ouvre l'ecran Findings avec les findings en memoire."""
        from hdwp.tui.screens.findings import FindingsScreen

        self.app.push_screen(
            FindingsScreen(db_url=self._get_db_url(), findings=self._findings)
        )

    def action_report(self) -> None:
        """[R] -- ouvre l'ecran Report."""
        from hdwp.tui.screens.report import ReportScreen

        llm_config = None
        if self._ctx:
            llm_config = self._ctx.config.llm
        self.app.push_screen(
            ReportScreen(db_url=self._get_db_url(), llm_config=llm_config)
        )

    def action_plugins(self) -> None:
        """[P] -- ouvre l'ecran Settings."""
        from hdwp.tui.screens.settings import SettingsScreen

        self.app.push_screen(SettingsScreen())

    def _get_db_url(self) -> str:
        from hdwp.core.paths import evidence_db_url

        return evidence_db_url(self._session_id)
