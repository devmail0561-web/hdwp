# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
log = structlog.get_logger()


@router.post("/proxy/start")
async def start_proxy(request: Request) -> dict:
    srv = request.app.state
    session = srv.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active")
    if session.proxy_active:
        return {"ok": True, "already_running": True, "port": 8080}

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
    log.info("proxy.started_manually", port=8080)
    return {"ok": True, "port": 8080}


@router.post("/proxy/stop")
async def stop_proxy(request: Request) -> dict:
    srv = request.app.state
    session = srv.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active")
    if not session.proxy_active:
        return {"ok": True, "was_running": False}

    if session.proxy_capture:
        try:
            await session.proxy_capture.stop()  # type: ignore[attr-defined]
        except Exception as exc:
            log.warning("proxy.stop_error", error=str(exc))

    if session.proxy_task and not session.proxy_task.done():
        session.proxy_task.cancel()

    session.proxy_active = False
    session.proxy_capture = None
    session.proxy_task = None
    log.info("proxy.stopped_manually")
    return {"ok": True}


@router.get("/proxy/ca-cert")
async def get_ca_cert() -> dict:
    from hdwp.core.observation.hdwp_proxy import CA_CERT_PATH
    if not CA_CERT_PATH.exists():
        return {"available": False, "path": str(CA_CERT_PATH)}
    return {
        "available": True,
        "path": str(CA_CERT_PATH),
        "pem": CA_CERT_PATH.read_text(encoding="utf-8"),
    }


@router.post("/proxy/install-ca")
async def install_ca_cert(request: Request) -> dict:
    """Installe le certificat CA HDWP dans tous les navigateurs détectés."""
    from hdwp.core.observation.ca_installer import install_ca_everywhere
    from hdwp.core.observation.hdwp_proxy import CA_CERT_PATH

    if not CA_CERT_PATH.exists():
        raise HTTPException(400, "Certificat CA non trouvé — lancez d'abord un scan pour le générer")

    results = install_ca_everywhere(CA_CERT_PATH)
    success_count = sum(1 for r in results.values() if r.get("ok"))
    return {
        "ok": True,
        "results": results,
        "summary": f"{success_count}/{len(results)} cibles configurées",
        "ca_path": str(CA_CERT_PATH),
    }
