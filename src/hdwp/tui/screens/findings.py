# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""FindingsScreen: browser interactif des findings confirmes."""
from __future__ import annotations

from typing import Any, ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Label, ListItem, ListView, Static


class FindingListItem(ListItem):
    """Un finding dans la liste."""

    def __init__(self, finding: dict[str, Any]) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        sev = self.finding.get("severity", "?")
        fid = self.finding.get("id", "?")
        ftype = self.finding.get("owasp_category", "")
        conf = f"{self.finding.get('confidence', 0):.0%}"
        yield Label(f"{fid} {sev} {ftype} {conf}")


class FindingsScreen(Screen):
    """Ecran d'affichage des findings avec liste + detail."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "pop_screen", "Retour"),
    ]

    def __init__(
        self,
        db_url: str = "",
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__()
        self._db_url = db_url
        self._findings: list[dict[str, Any]] = findings or []

    def compose(self) -> ComposeResult:
        with Horizontal(id="findings-layout"):
            with Vertical(id="findings-list-panel"):
                yield ListView(id="findings-list")
            with Vertical(id="findings-detail-panel"):
                yield Static("Selectionnez un finding", id="findings-detail")
        yield Footer()

    async def on_mount(self) -> None:
        # Si des findings sont passes en memoire, les utiliser directement
        if not self._findings and self._db_url:
            from hdwp.store.database import init_db
            from hdwp.store.repository import Repository

            engine_db = await init_db(self._db_url)
            repository = Repository(engine_db)
            raw_findings = await repository.list_findings(status="CONFIRMED")
            self._findings = [f.model_dump() for f in raw_findings]

        list_view = self.query_one("#findings-list", ListView)
        for f in self._findings:
            list_view.append(FindingListItem(f))

        self.query_one("#findings-detail", Static).update(
            f"{len(self._findings)} finding(s) confirme(s)"
        )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, FindingListItem):
            f = item.finding
            detail_lines = [
                f"ID       : {f.get('id', '?')}",
                f"TYPE     : {f.get('owasp_category', '?')} ({f.get('cwe_id', '?')})",
                f"SEVERITY : {f.get('severity', '?')}",
                f"CONF     : {f.get('confidence', 0):.0%}",
                f"ENDPOINT : {', '.join(f.get('affected_endpoints', []))}",
                "",
                "REMEDIATION :",
                f"  {f.get('remediation_hint', 'N/A')}",
            ]
            proof = f.get("proof", {})
            if isinstance(proof, dict):
                steps = proof.get("reproduction_steps", [])
                if steps:
                    detail_lines.append("")
                    detail_lines.append("REPRODUCTIONS :")
                    for step in steps:
                        detail_lines.append(f"  {step}")
            self.query_one("#findings-detail", Static).update("\n".join(detail_lines))
