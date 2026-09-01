# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class NormalizedRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any | None = None
    query_params: dict[str, str] = Field(default_factory=dict)
    path_params: dict[str, str] = Field(default_factory=dict)


class NormalizedResponse(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any | None = None
    content_type: str | None = None
    timing_ms: float = 0.0


class ObservationType(str, Enum):
    HTTP = "HTTP"
    DOM = "DOM"
    JS = "JS"
    COOKIE = "COOKIE"
    HEADER = "HEADER"
    WS = "WS"
    GRAPHQL = "GRAPHQL"


class RawObservation(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("OBS"))
    timestamp: str
    source: Literal["passive", "active"]
    type: ObservationType
    request: NormalizedRequest | None = None
    response: NormalizedResponse | None = None
    artefact: dict[str, Any] | None = None
    session_id: str
    tags: list[str] = Field(default_factory=list)


class EndpointNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("EP"))
    path: str
    methods: list[str] = Field(default_factory=list)
    auth_required: bool = False
    roles_observed: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    returns: list[str] = Field(default_factory=list)


class ParameterNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("PARAM"))
    name: str
    location: Literal["query", "body", "header", "path", "cookie"]
    type_inferred: Literal["integer", "string", "uuid", "boolean", "object", "array"] = "string"
    affects_object: str | None = None
    is_user_controlled: bool = True


class DataObjectNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("OBJ"))
    schema_def: dict[str, str] = Field(default_factory=dict, alias="schema")
    owner_parameter: str | None = None
    sensitivity: Literal["public", "private", "sensitive"] = "public"

    model_config = {"populate_by_name": True}


class RoleNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("ROLE"))
    name: str
    observed_permissions: list[str] = Field(default_factory=list)


class FSMState(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("FSM-S"))
    label: str
    observable_conditions: list[str] = Field(default_factory=list)


class FSMTransition(BaseModel):
    from_state: str
    to_state: str
    trigger: NormalizedRequest
    guard: str | None = None


class ApplicationFSM(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("FSM"))
    states: list[FSMState] = Field(default_factory=list)
    transitions: list[FSMTransition] = Field(default_factory=list)
    initial_state: str = ""
    confidence: float = 0.0


class ApplicationModelData(BaseModel):
    endpoints: list[EndpointNode] = Field(default_factory=list)
    parameters: list[ParameterNode] = Field(default_factory=list)
    objects: list[DataObjectNode] = Field(default_factory=list)
    roles: list[RoleNode] = Field(default_factory=list)
    relations: list[dict[str, Any]] = Field(default_factory=list)
    last_updated: str = ""
    fsm: ApplicationFSM | None = None


class PropertyType(str, Enum):
    AUTHORIZATION = "authorization"
    STATE = "state"
    INTEGRITY = "integrity"
    CONFIDENTIALITY = "confidentiality"
    COHERENCE = "coherence"
    TEMPORAL = "temporal"
    CONCURRENCY = "concurrency"


class SecurityProperty(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("PROP"))
    type: PropertyType
    formal_statement: str
    model_nodes: list[str] = Field(default_factory=list)
    inference_confidence: float = 0.0
    source_observations: list[str] = Field(default_factory=list)
    status: Literal["active", "invalidated"] = "active"


class HypothesisStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ExperimentSpec(BaseModel):
    mutation_type: str
    base_request: NormalizedRequest
    mutation_params: dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class Hypothesis(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("HYP"))
    status: HypothesisStatus = HypothesisStatus.PENDING
    source_plugin: str
    property_id: str
    statement: str
    observations_cited: list[str] = Field(default_factory=list)
    priority: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    priority_rationale: str = ""
    required_experiments: list[ExperimentSpec] = Field(default_factory=list)
    confidence: float = 0.0


class ExperimentResult(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("EXP"))
    hypothesis_id: str
    experiment_spec: ExperimentSpec
    request_sent: NormalizedRequest
    response_received: NormalizedResponse
    timing_ms: float = 0.0
    replayed_from: str | None = None
    timestamp: str = ""


class DiffVerdict(str, Enum):
    SIGNIFICANT = "SIGNIFICANT"
    INSIGNIFICANT = "INSIGNIFICANT"
    AMBIGUOUS = "AMBIGUOUS"


class SemanticDiff(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("DIFF"))
    exp_a: str
    exp_b: str
    structural_difference: bool = False
    behavioral_difference: bool = False
    leaked_fields: list[str] = Field(default_factory=list)
    status_difference: bool = False
    body_similarity: float = 0.0
    verdict: DiffVerdict = DiffVerdict.INSIGNIFICANT
    verdict_rationale: str = ""


class ConfidenceScore(BaseModel):
    oracle_strength: float = 0.0
    reproducibility: float = 0.0
    observation_quality: float = 0.0
    behavioral_specificity: float = 0.0
    experiment_coverage: float = 0.0
    overall: float = 0.0


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("FIND"))
    hypothesis_id: str
    property_id: str
    status: Literal["CONFIRMED", "REFUTED"]
    confidence: float
    confidence_breakdown: ConfidenceScore
    owasp_category: str = ""
    cwe_id: str = ""
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    affected_endpoints: list[str] = Field(default_factory=list)
    proof: dict[str, Any] = Field(default_factory=dict)
    remediation_hint: str = ""
