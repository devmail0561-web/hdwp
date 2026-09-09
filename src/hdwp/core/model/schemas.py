# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import uuid
from dataclasses import dataclass
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
    # Phase 2: raw bytes body override for smuggling/chunked strategies.
    # When set, engine._send() uses content=raw_body_override instead of normal body encoding.
    raw_body_override: bytes | None = None


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


class BehavioralProfile(BaseModel):
    """Profil statistique de la distribution de taille des réponses d'un endpoint."""
    mean: float = 0.0
    std: float = 1.0
    sample_count: int = 0
    max_zscore_seen: float | None = None  # plus haut |zscore| observé passivement


class EndpointNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("EP"))
    path: str
    methods: list[str] = Field(default_factory=list)
    auth_required: bool = False
    roles_observed: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    returns: list[str] = Field(default_factory=list)
    response_content_type: str | None = None  # MIME type de la réponse observée
    accepts_xml: bool = False                  # Endpoint accepte/retourne XML
    is_graphql: bool = False                   # Endpoint GraphQL détecté
    # Données comportementales exposées depuis ApplicationModel._behavioral_profiles
    behavioral_profile: BehavioralProfile | None = None
    # Dernier statut HTTP observé par rôle : {"user_a": 200, "anonymous": 403}
    status_by_role: dict[str, int] = Field(default_factory=dict)
    # Intelligence sémantique des réponses (peuplé par ResponseIntelligence)
    contains_privilege_field: bool = False      # body contient role/permissions/scope/is_admin
    observed_roles: list[str] = Field(default_factory=list)   # valeurs de rôles vues
    jwt_field_names: list[str] = Field(default_factory=list)  # champs qui contiennent des JWTs
    error_tech_signals: list[str] = Field(default_factory=list)  # ["oracle", "django", ...]
    detected_waf: str | None = None             # "waf:cloudflare", "waf:modsecurity", etc.


class ParameterNode(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("PARAM"))
    name: str
    location: Literal["query", "body", "header", "path", "cookie"]
    type_inferred: Literal["integer", "string", "uuid", "boolean", "object", "array"] = "string"
    affects_object: str | None = None
    is_user_controlled: bool = True
    semantic: str | None = None  # "file_path"|"url_redirect"|"xml_input"|"template_expr"|"id_ref"|"credential"


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
    tech_stack: list[str] = Field(default_factory=list)             # ["server:Apache/2.4", "framework:Django"]
    detected_content_types: list[str] = Field(default_factory=list) # ["application/json", "application/xml"]
    # Corpus de réponses par rôle : path_pattern → role_name → [body_dict, ...]
    # Peuplé par ApplicationModel, transmis aux modules d'inférence pour le cross-role diffing
    response_corpus: dict[str, dict[str, list[dict[str, Any]]]] = Field(default_factory=dict)
    # Versions détectées des frameworks : {"framework:django": "3.2.5"}
    detected_versions: dict[str, str] = Field(default_factory=dict)


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
    # Expérimentation adaptative : la condition est évaluée sur le résultat de mutation
    # Si True → les follow_up_specs sont ajoutés à la queue d'exécution
    trigger_condition: dict[str, Any] | None = None
    follow_up_specs: list[ExperimentSpec] = Field(default_factory=list)


# Pydantic v2 exige model_rebuild() pour les modèles auto-référentiels
ExperimentSpec.model_rebuild()


@dataclass
class ConcreteExperimentPlan:
    """Plan d'experience resolu, pret pour l'execution HTTP."""

    hypothesis_id: str
    mutation_type: str
    baseline_request: NormalizedRequest
    baseline_role: str
    target_role: str | None
    mutated_value: str | None
    mutated_param_name: str | None
    mutated_param_location: str | None
    description: str
    experiment_spec: ExperimentSpec


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
    disambiguation_attempts: int = 0  # garde contre les boucles infinies de désambiguïsation
    property_type: str | None = None  # clé d'arm bandit : PropertyType.value ou None


class ExperimentResult(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("EXP"))
    hypothesis_id: str
    experiment_spec: ExperimentSpec
    request_sent: NormalizedRequest
    response_received: NormalizedResponse
    timing_ms: float = 0.0
    replayed_from: str | None = None
    timestamp: str = ""
    is_baseline: bool = False  # True uniquement pour la requête témoin non-mutée


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
    data_identity_score: float | None = None  # 1.0=same user data, 0.0=different data, None=undetermined
    # Anomaly detection fields (unknown vulnerability indicators)
    response_size_ratio: float | None = None   # exp_size/base_size — >2.0 = potential data extraction
    response_zscore: float | None = None       # Z-score vs historical endpoint baseline — |z|>2.5 = anomaly
    suspicious_fields: list[str] = Field(default_factory=list)  # high-entropy/sensitive fields in exp
    security_headers_delta: dict[str, str] = Field(default_factory=dict)  # {header: "added"|"removed"}
    verdict: DiffVerdict = DiffVerdict.INSIGNIFICANT
    verdict_rationale: str = ""


class ConfidenceScore(BaseModel):
    oracle_strength: float = 0.0
    reproducibility: float = 0.0
    observation_quality: float = 0.0
    behavioral_specificity: float = 0.0
    experiment_coverage: float = 0.0
    overall: float = 0.0
    v2_boost: float = 0.0   # delta apporté par ConfidenceModelV2 (0 si non appliqué)
    ml_boost: float = 0.0   # delta apporté par OracleModel (0 si non appliqué)


class SignalContribution(BaseModel):
    dimension: str
    raw_value: float = 0.0
    weight: float = 0.0
    contribution: float = 0.0
    label: str = ""


class FindingExplanation(BaseModel):
    v1_score: float = 0.0
    v2_score: float = 0.0
    ml_score: float = 0.0
    signals: dict[str, float] = Field(default_factory=dict)
    top_contributors: list[SignalContribution] = Field(default_factory=list)
    verdict_rationale: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("FIND"))
    hypothesis_id: str
    property_id: str
    status: Literal["CONFIRMED", "REFUTED"]
    confidence: float
    confidence_breakdown: ConfidenceScore
    explanation: FindingExplanation | None = None
    owasp_category: str = ""
    cwe_id: str = ""
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    affected_endpoints: list[str] = Field(default_factory=list)
    proof: dict[str, Any] = Field(default_factory=dict)
    remediation_hint: str = ""

    # Threshold actif lors de la création du finding (Phase 0: config externalization)
    # Permet de revalider findings avec nouveaux thresholds sans incohérence
    confirmed_threshold_used: float = 0.85


# ── Flow Map schemas ─────────────────────────────────────────────────────────

class FlowEdgeType(str, Enum):
    PRODUCES = "PRODUCES"
    CONSUMES = "CONSUMES"
    TRANSFORMS = "TRANSFORMS"
    LEAKS = "LEAKS"


class FlowEdge(BaseModel):
    from_endpoint: str
    to_endpoint: str
    trigger: Literal["link", "form", "ajax", "fsm", "redirect"] = "link"
    edge_type: FlowEdgeType = FlowEdgeType.PRODUCES
    params_transferred: list[str] = Field(default_factory=list)
    confidence: float = 0.5


class DBColumn(BaseModel):
    name: str
    type_hint: str = "string"
    is_pk: bool = False
    is_fk_to: str | None = None


class DBTable(BaseModel):
    name: str
    columns: list[DBColumn] = Field(default_factory=list)
    evidence_endpoints: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class DataFlowMap(BaseModel):
    edges: list[FlowEdge] = Field(default_factory=list)
    db_tables: list[DBTable] = Field(default_factory=list)
    exfiltration_risks: list[str] = Field(default_factory=list)
    last_updated: str = ""


# ── Chain Attack schemas ──────────────────────────────────────────────────────

class ChainStep(BaseModel):
    step_index: int
    request: NormalizedRequest
    role_name: str = "anonymous"
    context_extractors: dict[str, str] = Field(default_factory=dict)
    inject_context: dict[str, str] = Field(default_factory=dict)


class ChainSpec(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("CHN"))
    chain_type: str
    steps: list[ChainStep]
    precondition_finding_ids: list[str] = Field(default_factory=list)
    description: str = ""
    executable: bool = True
    missing_preconditions: list[str] = Field(default_factory=list)
