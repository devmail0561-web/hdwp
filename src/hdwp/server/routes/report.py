# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hdwp.core.paths import reports_dir

router = APIRouter()


class ReportRequest(BaseModel):
    format: Literal["markdown", "json", "har", "sarif"] = "json"
    include_ai_summary: bool = False
    output_dir: str | None = None


@router.get("/report/default-dir")
async def get_default_report_dir(request: Request) -> dict:
    """Retourne le répertoire de rapport par défaut pour la session active."""
    session = request.app.state.server_state.get_active()
    if session:
        return {"path": str(reports_dir(session.session_id))}
    return {"path": str(Path.home() / ".hdwp" / "reports")}


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

    if req.output_dir:
        out_dir = Path(req.output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = reports_dir(session.session_id)

    try:
        if req.format == "json":
            await report_engine.generate_json(out_dir)
            output_path = str(out_dir / "findings.json")
        elif req.format == "har":
            await report_engine.generate_har(out_dir)
            output_path = str(out_dir / "har/")
        elif req.format == "sarif":
            sarif_path = await report_engine.generate_sarif(out_dir)
            output_path = str(sarif_path)
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


@router.get("/report/sarif")
async def get_sarif_report(request: Request) -> JSONResponse:
    """Génère et retourne le rapport SARIF 2.1.0 de la session active."""
    session = request.app.state.server_state.get_active()
    if not session:
        raise HTTPException(404, "Aucune session active")
    if not session.repository:
        raise HTTPException(400, "Repository non disponible pour cette session")

    if session.engine:
        report_engine = session.engine.report_engine
    else:
        from hdwp.core.bus.event_bus import AsyncEventBus
        from hdwp.core.report.engine import ReportEngine
        report_engine = ReportEngine(AsyncEventBus(), session.repository)

    out_dir = reports_dir(session.session_id)
    try:
        sarif_path = await report_engine.generate_sarif(out_dir)
    except Exception as exc:
        raise HTTPException(500, f"Erreur de génération SARIF : {exc}") from exc

    import json
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    return JSONResponse(content=sarif_data, media_type="application/json")
