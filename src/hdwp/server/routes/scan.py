# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, HTTPException, Request

from hdwp.server.models.scan import ScanStatusResponse

router = APIRouter()
log = structlog.get_logger()


@router.post("/scan/start", response_model=ScanStatusResponse)
async def start_scan(request: Request) -> ScanStatusResponse:
    srv = request.app.state
    session = srv.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active — créez une session d'abord")
    if session.status == "running":
        raise HTTPException(409, "Scan déjà en cours")

    from hdwp.server.event_bridge import EventBridge
    bridge = EventBridge(session.bus, srv.ws_manager, session_id=session.session_id)
    bridge.attach()

    # Mise à jour de la phase en temps réel depuis les événements du bus
    from hdwp.core.bus.events import (
        EXPERIMENT_RESULT, FINDING_CONFIRMED, HYPOTHESIS_GENERATED,
        MODEL_UPDATED, OBSERVATION_RAW, PROPERTY_INFERRED,
    )
    _PHASE_MAP = {
        OBSERVATION_RAW:     "OBSERVE",
        MODEL_UPDATED:       "MODEL",
        PROPERTY_INFERRED:   "INFER",
        HYPOTHESIS_GENERATED:"HYPOTHESIZE",
        EXPERIMENT_RESULT:   "EXPERIMENT",
        FINDING_CONFIRMED:   "FINDING",
    }
    for _evt, _phase in _PHASE_MAP.items():
        async def _phase_handler(event, p=_phase, e=_evt) -> None:  # noqa: ARG001
            session.phase = p
            if e == FINDING_CONFIRMED:
                session.findings_count += 1
        session.bus.on(_evt, _phase_handler)

    async def _run() -> None:
        try:
            session.set_status("running")

            # Appliquer la config LLM globale si elle existe
            llm_cfg = getattr(srv, "llm_config", None)
            if llm_cfg:
                from hdwp.core.context.config_schema import LLMConfig
                session.context.config.llm = LLMConfig(
                    enabled=llm_cfg.get("enabled", False),
                    provider=llm_cfg.get("provider", "anthropic"),  # type: ignore[arg-type]
                    model=llm_cfg.get("model", "claude-sonnet-4-6"),
                    base_url=llm_cfg.get("base_url"),
                )

            # Auto-démarrage du proxy MITM en mode découverte (HDWPProxy natif)
            if session.mode == "auto":
                try:
                    from hdwp.core.context.scope_guard import ScopeGuard
                    from hdwp.core.observation.hdwp_proxy import HDWPProxy
                    pc = HDWPProxy(
                        bus=session.bus,
                        scope_guard=ScopeGuard(session.context),
                        session_id=session.session_id,
                        port=8080,
                    )
                    session.proxy_capture = pc
                    session.proxy_task = asyncio.create_task(pc.start())
                    session.proxy_active = True
                    session._persist_metadata()
                    log.info("proxy.auto_started", port=8080)
                except Exception as exc:
                    log.warning("proxy.auto_start_failed", error=str(exc))

            # Le proxy MITM est pour le navigateur (Firefox) — le crawler contacte la cible directement.
            # Passer proxy_url=None : le crawl est direct, sans interception.
            proxy_url = None

            # Handler : ouvrir le navigateur sur la cible quand auth requise
            from hdwp.core.bus.events import AUTH_REQUIRED as _AUTH_REQ

            async def _on_auth_required(event) -> None:  # noqa: ARG001
                if session.proxy_active:
                    import webbrowser
                    webbrowser.open(session.target_url)
                    log.info("auth_required.browser_opened", target=session.target_url)

            session.bus.on(_AUTH_REQ, _on_auth_required)

            from hdwp.core.engine import HDWPEngine
            engine = await HDWPEngine.create_from_context(session.context, session.bus, proxy_url=proxy_url)
            session.engine = engine
            session.repository = engine._repository
            findings = await engine.run()
            session.findings_count = len(findings)
            session.phase = "DONE"
            session.set_status("done")

            from hdwp.core.bus.events import SCAN_COMPLETED
            await session.bus.emit(
                SCAN_COMPLETED,
                payload={"findings_count": len(findings)},
                source="engine",
            )

            await engine.close()
        except Exception as exc:
            log.error("scan.failed", error=str(exc), exc_info=True)
            session.error_message = str(exc)
            session.phase = "ERROR"
            session.set_status("error")

            from hdwp.core.bus.events import SCAN_ERROR
            await session.bus.emit(
                SCAN_ERROR,
                payload={"error": str(exc)},
                source="engine",
            )
            if session.engine:
                try:
                    await session.engine.close()
                except Exception:
                    pass
        finally:
            # Arrêt propre du proxy si actif
            if session.proxy_active and session.proxy_capture:
                try:
                    await session.proxy_capture.stop()  # type: ignore[attr-defined]
                except Exception:
                    pass
            if session.proxy_task and not session.proxy_task.done():
                session.proxy_task.cancel()
            session.proxy_active = False

    session.task = asyncio.create_task(_run())
    return ScanStatusResponse(status="running", session_id=session.session_id)


@router.post("/scan/stop")
async def stop_scan(request: Request) -> dict:
    srv = request.app.state
    session = srv.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active")
    if session.task and not session.task.done():
        session.task.cancel()
        # Wait for the task to finish unwinding before touching the engine.
        # Without this await, engine.close() races with _run()'s active use of
        # the engine (which hasn't yet received its CancelledError).
        try:
            await session.task
        except (asyncio.CancelledError, Exception):
            pass
    if session.engine:
        try:
            await session.engine.close()
        except Exception:
            pass
    session.set_status("done")
    return {"ok": True, "session_id": session.session_id}
