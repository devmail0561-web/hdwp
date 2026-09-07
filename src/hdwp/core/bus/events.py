# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

# HDWPEventMap — 12 event types from the v2 PDWST spec.
OBSERVATION_RAW = "observation.raw"
MODEL_UPDATED = "model.updated"
FSM_UPDATED = "fsm.updated"
PROPERTY_INFERRED = "property.inferred"
PROPERTY_INVALIDATED = "property.invalidated"
HYPOTHESIS_GENERATED = "hypothesis.generated"
HYPOTHESIS_STATUS_CHANGED = "hypothesis.status_changed"
EXPERIMENT_RESULT = "experiment.result"
DIFF_COMPUTED = "diff.computed"
FINDING_CONFIRMED = "finding.confirmed"
FINDING_REFUTED = "finding.refuted"
REPORT_GENERATED = "report.generated"
# Emis par ExperimentEngine quand tous les experiments d'une hypothese sont prets.
# Payload : {"hypothesis_id": str, "baseline_id": str, "experiment_ids": list[str]}
HYPOTHESIS_EXPERIMENTS_READY = "hypothesis.experiments_ready"
# Emis par ProxyCapture quand un token d'authentification est capturé dans le trafic proxy.
# Payload : {"token_type": str, "token_value": str, "role_name": str, "source_url": str}
CREDENTIALS_CAPTURED = "credentials.captured"
# Emis par FlowMapBuilder quand le flow map est reconstruit.
# Payload : DataFlowMap.model_dump()
FLOW_UPDATED = "flow.updated"
# Emis par ApplicationModel quand un endpoint nécessite une authentification non configurée.
# Payload : {"url": str, "path_pattern": str}
AUTH_REQUIRED = "auth.required"
SCAN_COMPLETED = "scan.completed"
SCAN_ERROR = "scan.error"
FINDINGS_CORRELATED = "findings.correlated"
# Emis par SemanticOracle quand une hypothèse retourne AMBIGUOUS/INSUFFICIENT_DATA.
# Payload : {"hypothesis_id": str, "mutation_type": str, "score": float, "diff_ids": list[str]}
HYPOTHESIS_AMBIGUOUS = "hypothesis.ambiguous"
# Emis par ApplicationModel quand un nouveau tag framework:/db:/cms: est détecté.
# Payload : {"tag": str}  ex: {"tag": "framework:laravel"}
TECH_STACK_UPDATED = "tech_stack.updated"
# ── V3 event types ───────────────────────────────────────────────────────────
THREAT_MODEL_UPDATED = "threat.model.updated"
INVARIANT_VIOLATED = "invariant.violated"
CROSSROLE_DIFF_CONFIRMED = "crossrole.diff.confirmed"
TEMPORAL_ANOMALY_DETECTED = "temporal.anomaly.detected"
PAYLOAD_ADAPTED = "payload.adapted"
WAF_SIGNATURE_DETECTED = "waf.signature.detected"
ATTACK_STATE_UPDATED = "attack.state.updated"
GOAL_REACHED = "goal.reached"
PRECONDITION_MISSING = "precondition.missing"

ALL_EVENT_TYPES = [
    OBSERVATION_RAW,
    MODEL_UPDATED,
    FSM_UPDATED,
    PROPERTY_INFERRED,
    PROPERTY_INVALIDATED,
    HYPOTHESIS_GENERATED,
    HYPOTHESIS_STATUS_CHANGED,
    EXPERIMENT_RESULT,
    DIFF_COMPUTED,
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    REPORT_GENERATED,
    HYPOTHESIS_EXPERIMENTS_READY,
    FLOW_UPDATED,
    AUTH_REQUIRED,
    CREDENTIALS_CAPTURED,
    SCAN_COMPLETED,
    SCAN_ERROR,
    FINDINGS_CORRELATED,
    HYPOTHESIS_AMBIGUOUS,
    TECH_STACK_UPDATED,
    THREAT_MODEL_UPDATED,
    INVARIANT_VIOLATED,
    CROSSROLE_DIFF_CONFIRMED,
    TEMPORAL_ANOMALY_DETECTED,
    PAYLOAD_ADAPTED,
    WAF_SIGNATURE_DETECTED,
    ATTACK_STATE_UPDATED,
    GOAL_REACHED,
    PRECONDITION_MISSING,
]


class HDWPEvent(BaseModel):
    type: str
    source: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    payload: Any = None
