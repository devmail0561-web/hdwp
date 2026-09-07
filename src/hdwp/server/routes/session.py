# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from hdwp.core.paths import evidence_db_url, workspace_dir
from hdwp.server.models.session import NewSessionRequest, SessionResponse
from hdwp.server.state import ScanSession, ServerState

router = APIRouter()


@router.post("/session/new", response_model=SessionResponse)
async def new_session(req: NewSessionRequest, request: Request) -> SessionResponse:
    srv_state = request.app.state.server_state
    context = _build_context(req)
    ctx_path = _resolve_context_path(req)
    session = srv_state.create_session(context, req.target_url, mode=req.mode, context_path=str(ctx_path))
    return SessionResponse(
        session_id=session.session_id,
        status=session.status,
        target_url=session.target_url,
    )


@router.get("/sessions")
async def list_sessions(request: Request) -> list[dict]:
    srv_state: ServerState = request.app.state.server_state
    in_memory = {s.session_id: s for s in srv_state.list_sessions()}
    disk_sessions = ServerState.list_sessions_from_disk()

    result: list[dict] = []
    seen: set[str] = set()

    for s in in_memory.values():
        seen.add(s.session_id)
        result.append({
            "session_id": s.session_id,
            "target_url": s.target_url,
            "status": s.status,
            "phase": s.phase,
            "created_at": s.created_at,
            "updated_at": datetime.now(UTC).isoformat(),
            "findings_count": s.findings_count,
            "mode": s.mode,
        })

    for d in disk_sessions:
        sid = d.get("session_id", "")
        if sid and sid not in seen:
            seen.add(sid)
            result.append(d)

    result.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return result[:50]


@router.delete("/session/{session_id}")
async def delete_session(session_id: str, request: Request) -> dict:
    """Archive (supprime) une session — efface le workspace disque."""
    srv_state: ServerState = request.app.state.server_state
    import shutil

    # Si session active en mémoire, la désactiver
    existing = srv_state.get(session_id)
    if existing:
        if srv_state._active_id == session_id:
            srv_state._active_id = None
        srv_state._sessions.pop(session_id, None)

    # Supprimer le workspace disque
    ws = workspace_dir(session_id)
    if ws.exists():
        try:
            shutil.rmtree(ws)
        except Exception as exc:
            raise HTTPException(500, f"Impossible de supprimer {ws}: {exc}") from exc

    return {"ok": True, "session_id": session_id}


@router.delete("/sessions")
async def delete_all_sessions(request: Request) -> dict:
    """Purge toutes les sessions — mémoire et disque."""
    import shutil

    from hdwp.core.paths import WORKSPACES_DIR

    srv_state: ServerState = request.app.state.server_state
    srv_state._sessions.clear()
    srv_state._active_id = None

    deleted = 0
    errors = 0
    if WORKSPACES_DIR.exists():
        for ws in WORKSPACES_DIR.iterdir():
            if ws.is_dir() and (ws / "session.json").exists():
                try:
                    shutil.rmtree(ws)
                    deleted += 1
                except Exception:
                    errors += 1

    return {"ok": True, "deleted": deleted, "errors": errors}


@router.post("/session/{session_id}/resume", response_model=SessionResponse)
async def resume_session(session_id: str, request: Request) -> SessionResponse:
    srv_state: ServerState = request.app.state.server_state

    existing = srv_state.get(session_id)
    if existing:
        srv_state.set_active(session_id)
        return SessionResponse(
            session_id=existing.session_id,
            status=existing.status,
            target_url=existing.target_url,
        )

    ws = workspace_dir(session_id)
    meta_path = ws / "session.json"
    if not meta_path.exists():
        raise HTTPException(404, f"Session {session_id} introuvable sur disque")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    target_url = meta.get("target_url", "")
    context_path_str = meta.get("context_path", "")
    status = meta.get("status", "done")
    mode = meta.get("mode", "auto")

    from hdwp.core.context.loader import ContextLoader
    from hdwp.core.paths import build_context_from_url
    ctx_path = Path(context_path_str).expanduser() if context_path_str else build_context_from_url(target_url)
    ctx = ContextLoader.load(ctx_path)
    # EngineContext est frozen — utiliser model_copy pour changer session_id
    ctx = ctx.model_copy(update={"session_id": session_id})

    from hdwp.store.database import init_db
    from hdwp.store.repository import Repository
    engine_db = await init_db(evidence_db_url(session_id))
    repo = Repository(engine_db)

    from hdwp.core.bus.event_bus import AsyncEventBus
    session = ScanSession(
        session_id=session_id,
        target_url=target_url,
        context=ctx,
        bus=AsyncEventBus(),
        status=status,
        repository=repo,
        mode=mode,
        context_path=context_path_str,
        created_at=meta.get("created_at", ""),
        findings_count=meta.get("findings_count", 0),
        phase=meta.get("phase", "DONE"),
    )
    srv_state.add_session(session)
    srv_state.set_active(session_id)
    return SessionResponse(session_id=session_id, status=status, target_url=target_url)


def _resolve_context_path(req: NewSessionRequest) -> Path:
    from hdwp.core.paths import build_context_from_url
    if req.mode == "yaml" and req.yaml_path:
        return Path(req.yaml_path)
    return build_context_from_url(req.target_url)


def _build_context(req: NewSessionRequest):  # type: ignore[return]
    from hdwp.core.context.loader import ContextLoader
    from hdwp.core.paths import build_context_from_url

    if req.mode == "yaml" and req.yaml_path:
        return ContextLoader.load(Path(req.yaml_path))

    ctx_path = build_context_from_url(req.target_url)
    ctx = ContextLoader.load(ctx_path)

    if req.mode == "manual" and req.manual_tokens:
        from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
        for tok in req.manual_tokens:
            role = RoleConfig(
                name=tok.role_name,
                credentials=CredentialConfig(
                    type=tok.token_type,  # type: ignore[arg-type]
                    token=tok.token_value,
                    username=tok.username,
                    password=tok.password,
                ),
            )
            ctx.config.roles.append(role)

    return ctx
