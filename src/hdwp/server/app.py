# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""FastAPI application — backend HDWP Engine."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from hdwp.server.state import ServerState
from hdwp.server.ws_manager import WebSocketManager


def create_app() -> FastAPI:
    """Factory FastAPI — appelée par uvicorn en mode factory."""
    app = FastAPI(title="HDWP Engine", version="0.1.0", docs_url="/api/docs")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # État global partagé entre toutes les routes
    app.state.server_state = ServerState()
    app.state.ws_manager = WebSocketManager()

    from hdwp.plugins.registry import PluginRegistry
    app.state.plugin_registry = PluginRegistry()
    app.state.plugin_registry.discover()

    from hdwp.core.knowledge.base import KnowledgeBase
    app.state.knowledge_base = KnowledgeBase()

    # Config LLM globale chargée depuis ~/.hdwp/llm_config.json
    from hdwp.server.routes.llm import _LLM_CONFIG_PATH
    import json as _json
    if _LLM_CONFIG_PATH.exists():
        try:
            app.state.llm_config = _json.loads(_LLM_CONFIG_PATH.read_text())
        except Exception:
            app.state.llm_config = None
    else:
        app.state.llm_config = None

    # Routes API
    from hdwp.server.routes.exploit import router as exploit_router
    from hdwp.server.routes.findings import router as findings_router
    from hdwp.server.routes.flow import router as flow_router
    from hdwp.server.routes.health import router as health_router
    from hdwp.server.routes.knowledge import router as knowledge_router
    from hdwp.server.routes.llm import router as llm_router
    from hdwp.server.routes.models import router as models_router
    from hdwp.server.routes.plugins import router as plugins_router
    from hdwp.server.routes.proxy import router as proxy_router
    from hdwp.server.routes.report import router as report_router
    from hdwp.server.routes.scan import router as scan_router
    from hdwp.server.routes.session import router as session_router
    from hdwp.server.routes.state_route import router as state_router

    app.include_router(health_router, prefix="/api")
    app.include_router(session_router, prefix="/api")
    app.include_router(scan_router, prefix="/api")
    app.include_router(state_router, prefix="/api")
    app.include_router(findings_router, prefix="/api")
    app.include_router(plugins_router, prefix="/api")
    app.include_router(proxy_router, prefix="/api")
    app.include_router(report_router, prefix="/api")
    app.include_router(exploit_router, prefix="/api")
    app.include_router(flow_router, prefix="/api")
    app.include_router(knowledge_router, prefix="/api")
    app.include_router(llm_router, prefix="/api")
    app.include_router(models_router, prefix="/api")

    # WebSocket — stream bus events → clients
    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket) -> None:
        await app.state.ws_manager.connect(ws)
        try:
            while True:
                await ws.receive_text()  # keep-alive, messages entrants ignorés
        except WebSocketDisconnect:
            pass
        finally:
            await app.state.ws_manager.disconnect(ws)

    # Servir le frontend React (production uniquement — dist/ doit exister)
    dist = Path(__file__).parent.parent / "app" / "dist"
    if dist.exists():
        from fastapi.staticfiles import StaticFiles
        # Mount APRÈS toutes les routes /api/* et /ws/*
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")

    return app
