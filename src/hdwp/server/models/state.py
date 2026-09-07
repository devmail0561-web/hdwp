# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from pydantic import BaseModel


class StateResponse(BaseModel):
    status: str = "idle"
    session_id: str = ""
    target_url: str = ""
    phase: str = "IDLE"
    model_confidence: float = 0.0
    endpoint_count: int = 0
    hypothesis_count: int = 0
    findings_count: int = 0
    property_count: int = 0
    experiment_count: int = 0
    proxy_active: bool = False
    error_message: str = ""
    # Enrichissement tech stack et versions (pour le frontend)
    tech_stack: list[str] = []
    detected_versions: dict[str, str] = {}
    detected_content_types: list[str] = []
    # V3 intelligence fields
    threat_score_max: float = 0.0
    invariant_violation_count: int = 0
    invariant_count: int = 0
    waf_detected: bool = False


class LLMStatusResponse(BaseModel):
    active: bool = False
    provider: str | None = None
    model: str | None = None
    api_key_valid: bool = False
