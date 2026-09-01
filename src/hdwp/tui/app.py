# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
HDWPApp: main Textual TUI application.

Screen routing:
  - TargetScreen (default) -> [ENTER] -> ScanScreen
  - ScanScreen -> [F] -> FindingsScreen -> [ESC]
  - ScanScreen -> [R] -> ReportScreen -> [ESC]
  - ScanScreen -> [P] -> SettingsScreen -> [ESC]
  - hdwp run --target URL -> ScanScreen directly (skip TargetScreen)
"""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer

from hdwp.tui.widgets import HdwpHeader


class HDWPApp(App):
    """HDWP Engine -- hacker terminal TUI."""

    CSS_PATH = Path(__file__).parent / "hdwp.tcss"

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(
        self,
        context_path: Path | None = None,
        db_url: str | None = None,
        auto_start_url: str | None = None,
    ) -> None:
        super().__init__()
        self._context_path = context_path
        self._db_url = db_url
        self._auto_start_url = auto_start_url

    def compose(self) -> ComposeResult:
        yield HdwpHeader(id="hdwp-header")
        yield Footer()

    def on_mount(self) -> None:
        from hdwp.tui.screens.target import TargetScreen

        if self._auto_start_url:
            # Skip TargetScreen, go directly to ScanScreen
            from hdwp.tui.screens.scan import ScanScreen

            self.push_screen(
                ScanScreen(
                    target_url=self._auto_start_url,
                    context_path=self._context_path,
                    mode="auto",
                )
            )
        else:
            self.push_screen(TargetScreen())

    def action_quit(self) -> None:
        self.exit()
