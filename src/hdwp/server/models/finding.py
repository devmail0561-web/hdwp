# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from pydantic import BaseModel


class ConfidenceBreakdown(BaseModel):
    oracle_strength: float = 0.0
    reproducibility: float = 0.0
    observation_quality: float = 0.0
    behavioral_specificity: float = 0.0
    experiment_coverage: float = 0.0
    overall: float = 0.0


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
    # Champs enrichis — toujours présents (défaut vide pour rétro-compatibilité)
    confidence_breakdown: ConfidenceBreakdown = ConfidenceBreakdown()
    proof: dict = {}
