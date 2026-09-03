# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from fastapi import APIRouter, Request

from hdwp.server.models.finding import FindingResponse

router = APIRouter()


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(request: Request) -> list[FindingResponse]:
    session = request.app.state.server_state.get_active()
    if not session or not session.repository:
        return []
    findings = await session.repository.list_findings(status="CONFIRMED")
    return [
        FindingResponse(
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
        )
        for f in findings
    ]
