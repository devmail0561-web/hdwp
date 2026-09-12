# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import date
from pathlib import Path

from fastapi import APIRouter, Request

from hdwp.server.models.finding import ConfidenceBreakdown, FindingResponse

router = APIRouter()


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(request: Request) -> list[FindingResponse]:
    session = request.app.state.server_state.get_active()
    if not session or not session.repository:
        return []
    findings = await session.repository.list_findings()
    result = []
    for f in findings:
        cb = f.confidence_breakdown
        breakdown = ConfidenceBreakdown(
            oracle_strength=cb.oracle_strength if cb else 0.0,
            reproducibility=cb.reproducibility if cb else 0.0,
            observation_quality=cb.observation_quality if cb else 0.0,
            behavioral_specificity=cb.behavioral_specificity if cb else 0.0,
            experiment_coverage=cb.experiment_coverage if cb else 0.0,
            overall=cb.overall if cb else f.confidence,
        ) if cb else ConfidenceBreakdown(overall=f.confidence)
        result.append(FindingResponse(
            id=f.id,
            hypothesis_id=f.hypothesis_id,
            property_id=f.property_id,
            status=f.status,
            severity=f.severity,
            confidence=f.confidence,
            owasp_category=f.owasp_category,
            cwe_id=f.cwe_id,
            affected_endpoints=f.affected_endpoints,
            remediation_hint=f.remediation_hint,
            confidence_breakdown=breakdown,
            proof=f.proof if isinstance(f.proof, dict) else {},
        ))
    return result


@router.post("/findings/export")
async def export_findings(request: Request) -> dict:
    import json

    session = request.app.state.server_state.get_active()
    rows: list[dict] = []
    if session and session.repository:
        for f in await session.repository.list_findings():
            rows.append({
                "id": f.id,
                "hypothesis_id": f.hypothesis_id,
                "property_id": f.property_id,
                "status": f.status,
                "severity": f.severity,
                "confidence": f.confidence,
                "owasp_category": f.owasp_category,
                "cwe_id": f.cwe_id,
                "affected_endpoints": f.affected_endpoints,
                "remediation_hint": f.remediation_hint,
            })
    filename = f"hdwp-findings-{date.today().isoformat()}.json"
    desktop = Path.home() / "Bureau"
    if not desktop.exists():
        desktop = Path.home() / "Desktop"
    if not desktop.exists():
        desktop = Path.home()
    out = desktop / filename
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"path": str(out), "count": len(rows)}
