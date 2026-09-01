# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Custom Textual widgets for the HDWP TUI."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Label, Log, ProgressBar, Static

HDWP_LOGO = """\
 ██╗  ██╗██████╗ ██╗    ██╗██████╗
 ██║  ██║██╔══██╗██║    ██║██╔══██╗
 ███████║██║  ██║██║ █╗ ██║██████╔╝
 ██╔══██║██║  ██║██║███╗██║██╔═══╝
 ██║  ██║██████╔╝╚███╔███╔╝██║
 ╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝╚═╝"""


class HdwpHeader(Static):
    """ASCII art logo with version and session ID."""

    DEFAULT_CSS = """
    HdwpHeader {
        height: 8;
        content-align: center middle;
        color: #00ff41;
        background: #0a0a0a;
        border-bottom: solid #1a3a1a;
        text-style: bold;
    }
    """

    def __init__(self, session_id: str = "", **kwargs: Any) -> None:
        import hdwp as _hdwp

        v = _hdwp.__version__
        sid = session_id[:20] if session_id else "no session"
        super().__init__(f"{HDWP_LOGO}\n   v{v}  |  {sid}", **kwargs)

    def set_session(self, session_id: str) -> None:
        import hdwp as _hdwp

        v = _hdwp.__version__
        self.update(f"{HDWP_LOGO}\n   v{v}  |  {session_id[:20]}")


class StatusPanel(Widget):
    """Engine status panel with progress bars."""

    DEFAULT_CSS = """
    StatusPanel {
        width: 40;
        border: solid #1a3a1a;
        color: #00ff41;
        padding: 0 1;
        background: #050d05;
    }
    StatusPanel Label { color: #00cc33; }
    #status-label { color: #00ff41; text-style: bold; }
    #proxy-label { color: #445566; }
    #target-label { color: #d8d8e8; }
    #crawl-bar { width: 30; }
    #crawl-bar .bar--bar { background: #00d4ff; }
    #props-bar .bar--bar { background: #cc44ff; }
    #experiments-bar .bar--bar { background: #ff6b35; }
    #hyp-label { color: #4488ff; }
    #exp-label { color: #ff6b35; }
    """

    def compose(self) -> ComposeResult:
        yield Label("  IDLE", id="status-label")
        yield Label("  PROXY ---", id="proxy-label")
        yield Label("", id="target-label")
        yield Label("Crawl", id="crawl-phase-label")
        yield ProgressBar(total=100, show_eta=False, id="crawl-bar")
        yield Label("", id="hyp-label")
        yield Label("", id="exp-label")

    def update_status(self, phase: str, progress: float, detail: str = "") -> None:
        label_map = {
            "crawl": "  CRAWLING",
            "properties": "  INFERRING",
            "experiments": "  TESTING",
            "done": " COMPLETE",
            "error": " ERROR",
        }
        self.query_one("#status-label", Label).update(
            label_map.get(phase, f"  {phase.upper()}")
        )
        self.query_one("#crawl-bar", ProgressBar).progress = round(progress * 100)
        if detail:
            self.query_one("#target-label", Label).update(detail)

    def set_target(self, url: str) -> None:
        self.query_one("#target-label", Label).update(f"  {url[:35]}")

    def set_proxy_status(self, active: bool) -> None:
        label = self.query_one("#proxy-label", Label)
        if active:
            label.update("  PROXY 127.0.0.1:8080")
            label.styles.color = "#00ff41"
        else:
            label.update("  PROXY ---")
            label.styles.color = "#445566"

    def update_hypotheses(self, count: int, high: int = 0, medium: int = 0) -> None:
        self.query_one("#hyp-label", Label).update(
            f"Hypotheses  {count} (HIGH:{high} MED:{medium})"
        )

    def update_experiments(self, done: int, total: int) -> None:
        self.query_one("#exp-label", Label).update(f"Experiments {done}/{total}")


class EventLogPanel(Log):
    """Real-time scrollable event feed from the HDWP bus."""

    DEFAULT_CSS = """
    EventLogPanel {
        border: solid #1a1a3a;
        color: #00bfff;
        background: #05050d;
        height: 1fr;
    }
    """

    _EVENT_COLORS: ClassVar[dict[str, str]] = {
        "OBS": "#00d4ff",
        "PROP": "#cc44ff",
        "HYP": "#ff6b35",
        "EXP": "#4488ff",
        "V": "#44ff88",
        "X": "#ff2244",
        "KEY": "#ffd700",
        "ERR": "#ff0000",
    }

    def add_event(self, event_type: str, message: str) -> None:
        now = datetime.now(UTC).strftime("%H:%M:%S")
        color = self._EVENT_COLORS.get(event_type, "")
        if color:
            self.write_line(f"{now} [{color}][{event_type}][/{color}]  {message}")
        else:
            self.write_line(f"{now} [{event_type}]  {message}")


class FindingsTable(DataTable):
    """Live-updating findings table."""

    DEFAULT_CSS = """
    FindingsTable {
        height: 12;
        border: solid #3a1a1a;
        background: #0d0505;
    }
    FindingsTable .datatable--header {
        color: #888888;
        background: #1a0a0a;
    }
    FindingsTable .datatable--cursor { background: #2a1a1a; }
    .new-finding {
        background: #2a0a00;
        text-style: bold;
    }
    """

    _SEV_COLORS: ClassVar[dict[str, str]] = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue",
    }

    _SEV_BARS: ClassVar[dict[str, str]] = {
        "CRITICAL": "[red]####[/red]",
        "HIGH": "[red]###-[/red]",
        "MEDIUM": "[yellow]##--[/yellow]",
        "LOW": "[green]#---[/green]",
        "INFO": "[blue]----[/blue]",
    }

    def on_mount(self) -> None:
        self.add_columns("ID", "SEV", "TYPE", "OWASP", "CWE", "CONF")
        self.cursor_type = "row"

    def add_finding(self, finding: dict[str, Any]) -> None:
        severity = finding.get("severity", "INFO")
        bars = self._SEV_BARS.get(severity, "[white]----[/white]")
        owasp = finding.get("owasp_category", "")
        cwe = finding.get("cwe_id", "")
        conf = f"{finding.get('confidence', 0):.0%}"
        vuln_type = _guess_vuln_type(owasp, cwe, finding)
        self.add_row(
            finding.get("id", "?"),
            bars,
            vuln_type,
            owasp,
            cwe,
            conf,
        )
        # Flash visuel 2 secondes pour les nouveaux findings
        self.add_class("new-finding")
        self.set_timer(2.0, lambda: self.remove_class("new-finding"))


def _guess_vuln_type(owasp: str, cwe: str, finding: dict[str, Any]) -> str:
    proof = finding.get("proof", {})
    mutation = proof.get("mutation_type", "") if isinstance(proof, dict) else ""
    match mutation:
        case "identity_swap":
            return "BOLA"
        case "object_ref_change":
            return "IDOR"
        case "privilege_escalation":
            return "AuthZ"
        case "jwt_manipulation":
            return "JWT"
        case "origin_test":
            return "CORS"
        case "field_injection":
            return "Injection"
    if cwe == "CWE-942":
        return "CORS"
    if cwe == "CWE-89":
        return "SQLi"
    if cwe == "CWE-79":
        return "XSS"
    if owasp == "A05:2021":
        return "Config"
    return "Unknown"
