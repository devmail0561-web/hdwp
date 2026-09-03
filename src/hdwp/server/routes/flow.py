# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()

_EMPTY: dict = {"edges": [], "db_tables": [], "exfiltration_risks": [], "last_updated": ""}


@router.get("/flow/map")
async def get_flow_map(request: Request) -> dict:
    session = request.app.state.server_state.get_active()
    if not session:
        return _EMPTY

    # Return cached map if available
    if session.engine and getattr(session.engine._app_model, "_last_flow_map", None) is not None:
        return session.engine._app_model._last_flow_map.model_dump()

    # Build on demand from snapshot (e.g. resumed session)
    if not session.engine:
        return _EMPTY

    try:
        from hdwp.core.model.flow_map_builder import FlowMapBuilder
        snap = session.engine._app_model.snapshot()
        builder = FlowMapBuilder()
        # Reuse accumulated edge counts from the engine's builder
        if hasattr(session.engine._app_model, "_flow_builder"):
            builder._edge_counts = dict(session.engine._app_model._flow_builder._edge_counts)
        return builder.build(snap).model_dump()
    except Exception:
        return _EMPTY
