# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""ReportScreen: generation de rapports depuis le TUI."""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, RadioSet, Static

from hdwp.core.context.config_schema import LLMConfig


class ReportScreen(Screen):
    """Ecran de generation de rapport."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "pop_screen", "Retour"),
        Binding("enter", "generate", "Generer"),
    ]

    def __init__(self, db_url: str, llm_config: LLMConfig | None = None) -> None:
        super().__init__()
        self._db_url = db_url
        self._llm_config = llm_config

    def compose(self) -> ComposeResult:
        with Vertical(id="report-container"):
            yield Static("GENERER UN RAPPORT", id="report-title")
            yield Label("Format :", id="format-label")
            yield RadioSet(
                "Markdown",
                "JSON",
                "HAR",
                id="format-radio",
            )
            yield Label("Fichier :", id="file-label")
            yield Input(
                placeholder="~/.hdwp/workspaces/SESSION-xxx/reports/report.md",
                id="file-input",
            )
            yield Label("Resume IA :", id="llm-label")
            yield RadioSet(
                "Active (claude-sonnet)",
                "Desactive",
                id="llm-radio",
            )
            with Vertical(id="report-buttons"):
                yield Button("[ENTER] Generer", id="generate-btn", variant="primary")
                yield Button("[ESC] Retour", id="back-btn", variant="default")

    def _get_selected_format(self) -> str:
        radio = self.query_one("#format-radio", RadioSet)
        match radio.pressed_index:
            case 0:
                return "md"
            case 1:
                return "json"
            case 2:
                return "har"
            case _:
                return "md"

    def _is_llm_active(self) -> bool:
        radio = self.query_one("#llm-radio", RadioSet)
        return radio.pressed_index == 0

    async def action_generate(self) -> None:
        """[ENTER] -- generer le rapport."""
        from hdwp.core.bus.event_bus import AsyncEventBus
        from hdwp.core.report.engine import ReportEngine
        from hdwp.store.database import init_db
        from hdwp.store.repository import Repository

        fmt = self._get_selected_format()
        file_input = self.query_one("#file-input", Input).value.strip()

        engine_db = await init_db(self._db_url)
        repository = Repository(engine_db)
        bus = AsyncEventBus()
        report_engine = ReportEngine(bus, repository)

        llm_layer = None
        if self._is_llm_active() and self._llm_config and self._llm_config.enabled:
            from hdwp.core.llm.layer import create_llm_layer

            llm_layer = create_llm_layer(self._llm_config)

        try:
            match fmt:
                case "md":
                    out = Path(file_input) if file_input else Path("report.md")
                    await report_engine.generate_markdown(
                        out, llm_layer=llm_layer
                    )
                    self.notify(
                        f"Rapport Markdown : {out}",
                        severity="information",
                        timeout=3.0,
                    )
                case "json":
                    out = Path(file_input) if file_input else Path("report_json")
                    summary = await report_engine.generate_json(out)
                    self.notify(
                        f"Rapport JSON : {out}/ ({summary['total']} finding(s))",
                        severity="information",
                        timeout=3.0,
                    )
                case "har":
                    out = Path(file_input) if file_input else Path("report_har")
                    await report_engine.generate_har(out)
                    self.notify(
                        f"Fichiers HAR : {out}/",
                        severity="information",
                        timeout=3.0,
                    )
        except (OSError, ValueError) as exc:
            self.notify(f"Erreur : {exc}", severity="error", timeout=5.0)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "generate-btn":
                self.app.run_worker(self.action_generate(), exclusive=True)
            case "back-btn":
                self.app.pop_screen()
