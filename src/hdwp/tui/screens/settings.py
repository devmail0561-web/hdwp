# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SettingsScreen: plugins, knowledge base, sessions."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static, TabbedContent, TabPane


class SettingsScreen(Screen):
    """Ecran de configuration : plugins, knowledge, sessions."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "pop_screen", "Retour"),
    ]

    def __init__(self) -> None:
        super().__init__()

    def compose(self) -> ComposeResult:
        with TabbedContent("Plugins", "Knowledge", "Sessions", id="settings-tabs"):
            with TabPane("Plugins", id="plugins-tab"):
                yield self._build_plugins_tab()
            with TabPane("Knowledge", id="knowledge-tab"):
                yield self._build_knowledge_tab()
            with TabPane("Sessions", id="sessions-tab"):
                yield self._build_sessions_tab()
        yield Footer()

    def _build_plugins_tab(self) -> DataTable:
        from hdwp.plugins.registry import PluginRegistry

        registry = PluginRegistry()
        registry.discover()
        table = DataTable(id="plugins-table")
        table.add_columns("ID", "Nom", "Categorie", "OWASP", "Version", "Statut")
        for p in registry.list_all():
            status = "enabled" if p.id in registry._enabled else "disabled"
            table.add_row(
                p.id, p.name, p.category, ", ".join(p.owasp_mapping), p.version, status
            )
        return table

    def _build_knowledge_tab(self) -> Static:
        return Static(
            "Knowledge Base\n\n"
            "Chargement des statistiques...\n"
            "(utilisez 'hdwp knowledge stats' en CLI pour plus de details)"
        )

    def _build_sessions_tab(self) -> DataTable:
        from hdwp.core.paths import WORKSPACES_DIR

        table = DataTable(id="sessions-table")
        table.add_columns("Session", "Date", "DB Size")
        if WORKSPACES_DIR.exists():
            for ws in sorted(WORKSPACES_DIR.iterdir(), reverse=True):
                if not ws.is_dir():
                    continue
                db_file = ws / "evidence.db"
                size = (
                    f"{db_file.stat().st_size // 1024}KB"
                    if db_file.exists()
                    else "---"
                )
                mtime = datetime.fromtimestamp(
                    ws.stat().st_mtime, tz=UTC
                ).strftime("%Y-%m-%d %H:%M")
                table.add_row(ws.name, mtime, size)
        return table
