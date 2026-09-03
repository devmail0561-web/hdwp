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
]


class HDWPEvent(BaseModel):
    type: str
    source: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    payload: Any = None
