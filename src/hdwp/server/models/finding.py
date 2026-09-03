# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    hypothesis_id: str
    property_id: str
    status: str
    severity: str
    confidence: float
    owasp_category: str = ""
    cwe_id: str = ""
    affected_endpoints: list[str] = []
    remediation_hint: str = ""
