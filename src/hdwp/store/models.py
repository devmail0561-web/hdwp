# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ObservationRecord(SQLModel, table=True):
    __tablename__ = "observations"
    id: str = Field(primary_key=True)
    timestamp: str
    source: str
    type: str
    session_id: str
    data_json: str
    created_at: str = Field(default_factory=_now_iso)


class PropertyRecord(SQLModel, table=True):
    __tablename__ = "properties"
    id: str = Field(primary_key=True)
    type: str
    status: str
    inference_confidence: float
    data_json: str
    created_at: str = Field(default_factory=_now_iso)


class HypothesisRecord(SQLModel, table=True):
    __tablename__ = "hypotheses"
    id: str = Field(primary_key=True)
    property_id: str | None = None
    status: str
    priority: str
    source_plugin: str | None = None
    confidence: float = 0.0
    data_json: str
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)


class ExperimentRecord(SQLModel, table=True):
    __tablename__ = "experiments"
    id: str = Field(primary_key=True)
    hypothesis_id: str
    timing_ms: float | None = None
    data_json: str
    created_at: str = Field(default_factory=_now_iso)


class DiffRecord(SQLModel, table=True):
    __tablename__ = "diffs"
    id: str = Field(primary_key=True)
    exp_a: str
    exp_b: str
    verdict: str
    data_json: str
    created_at: str = Field(default_factory=_now_iso)


class FindingRecord(SQLModel, table=True):
    __tablename__ = "findings"
    id: str = Field(primary_key=True)
    hypothesis_id: str
    property_id: str | None = None
    status: str
    severity: str | None = None
    owasp_category: str | None = None
    cwe_id: str | None = None
    confidence: float
    data_json: str
    created_at: str = Field(default_factory=_now_iso)


class ChainFindingRecord(SQLModel, table=True):
    __tablename__ = "chain_findings"
    id: str = Field(primary_key=True)
    session_id: str
    chain_type: str
    trigger_finding_ids: str   # JSON list
    severity: str
    confidence: float
    data_json: str             # ChainFinding.proof + step metadata
    created_at: str = Field(default_factory=_now_iso)


class ModelSnapshotRecord(SQLModel, table=True):
    __tablename__ = "model_snapshots"
    id: str = Field(primary_key=True)
    data_json: str
    created_at: str = Field(default_factory=_now_iso)
