# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from hdwp.core.paths import WORKSPACES_DIR, workspace_dir

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.context.loader import EngineContext
    from hdwp.core.engine import HDWPEngine
    from hdwp.store.repository import Repository

log = structlog.get_logger()


@dataclass
class ScanSession:
    session_id: str
    target_url: str
    context: EngineContext
    bus: AsyncEventBus
    status: str = "ready"
    engine: HDWPEngine | None = None
    repository: Repository | None = None
    task: asyncio.Task | None = None
    phase: str = "IDLE"
    proxy_active: bool = False
    proxy_capture: Any = None   # ProxyCapture | None — Any pour éviter import circulaire
    proxy_task: asyncio.Task | None = None
    error_message: str = ""
    findings_count: int = 0
    created_at: str = ""
    mode: str = "auto"
    context_path: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(UTC).isoformat()

    def set_status(self, new_status: str) -> None:
        self.status = new_status
        self._persist_metadata()

    def _persist_metadata(self) -> None:
        ws = workspace_dir(self.session_id)
        ws.mkdir(parents=True, exist_ok=True)
        meta = {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at,
            "updated_at": datetime.now(UTC).isoformat(),
            "findings_count": self.findings_count,
            "mode": self.mode,
            "context_path": self.context_path,
        }
        meta_path = ws / "session.json"
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        log.debug("session.metadata_saved", session_id=self.session_id)


class ServerState:
    """État global du serveur — sessions de scan."""

    def __init__(self) -> None:
        self._sessions: dict[str, ScanSession] = {}
        self._active_id: str | None = None

    def create_session(
        self,
        context: EngineContext,
        target_url: str,
        mode: str = "auto",
        context_path: str = "",
    ) -> ScanSession:
        from hdwp.core.bus.event_bus import AsyncEventBus
        session = ScanSession(
            session_id=context.session_id,
            target_url=target_url,
            context=context,
            bus=AsyncEventBus(),
            mode=mode,
            context_path=context_path,
        )
        self._sessions[session.session_id] = session
        self._active_id = session.session_id
        session._persist_metadata()
        return session

    def add_session(self, session: ScanSession) -> None:
        self._sessions[session.session_id] = session

    def set_active(self, session_id: str) -> None:
        self._active_id = session_id

    def get_active(self) -> ScanSession | None:
        return self._sessions.get(self._active_id) if self._active_id else None

    def get(self, session_id: str) -> ScanSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[ScanSession]:
        return list(self._sessions.values())

    @staticmethod
    def list_sessions_from_disk() -> list[dict]:
        """Scan ~/.hdwp/workspaces/*/session.json for persisted session metadata."""
        results: list[dict] = []
        if not WORKSPACES_DIR.exists():
            return results
        for meta_path in WORKSPACES_DIR.glob("*/session.json"):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                results.append(data)
            except Exception:
                continue
        return results
