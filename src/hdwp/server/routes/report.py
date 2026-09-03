# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hdwp.core.paths import reports_dir

router = APIRouter()


class ReportRequest(BaseModel):
    format: Literal["markdown", "json", "har"] = "json"
    include_ai_summary: bool = False


@router.post("/report/generate")
async def generate_report(req: ReportRequest, request: Request) -> dict:
    session = request.app.state.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active")
    if not session.repository:
        raise HTTPException(400, "Repository non disponible pour cette session")

    # Construire le ReportEngine — fonctionne avec ou sans moteur actif
    if session.engine:
        report_engine = session.engine.report_engine
        llm_layer = session.engine._llm_layer if req.include_ai_summary else None
    else:
        from hdwp.core.bus.event_bus import AsyncEventBus
        from hdwp.core.report.engine import ReportEngine
        report_engine = ReportEngine(AsyncEventBus(), session.repository)
        llm_layer = None

    out_dir = reports_dir(session.session_id)

    try:
        if req.format == "json":
            await report_engine.generate_json(out_dir)
            output_path = str(out_dir / "findings.json")
        elif req.format == "har":
            await report_engine.generate_har(out_dir)
            output_path = str(out_dir / "har/")
        else:  # markdown
            md_path = out_dir / "report.md"
            await report_engine.generate_markdown(
                md_path,
                llm_layer=llm_layer,
                target=session.target_url,
            )
            output_path = str(md_path)
    except Exception as exc:
        raise HTTPException(500, f"Erreur de génération : {exc}") from exc

    return {
        "ok": True,
        "path": output_path,
        "format": req.format,
        "ai_summary_included": bool(llm_layer),
    }
