# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from sqlmodel import Field, SQLModel


class PatternStatsRecord(SQLModel, table=True):
    __tablename__ = "pattern_stats"
    property_type: str = Field(primary_key=True)
    mutation_type: str = Field(primary_key=True)
    target_type: str = Field(default="unknown", primary_key=True)
    confirmed_count: int = 0
    refuted_count: int = 0
    total_count: int = 0
    avg_confidence: float = 0.0
    last_updated: str = ""


class SessionMetaRecord(SQLModel, table=True):
    __tablename__ = "session_meta"
    session_id: str = Field(primary_key=True)
    target_hash: str = ""
    findings_count: int = 0
    ended_at: str = ""
    endpoint_count: int = 0
    role_count: int = 0
    bola_param_count: int = 0
    target_type: str = "unknown"


class TrainingSampleOracleRecord(SQLModel, table=True):
    """Échantillon d'entraînement pour l'OracleModel (Phase 1)."""
    __tablename__ = "training_samples_oracle"
    id: str = Field(primary_key=True)
    diff_embedding: str = ""      # json.dumps(list[float])
    mutation_type: str = ""
    verdict: str = ""             # "CONFIRMED" | "REFUTED" | "AMBIGUOUS"
    human_validated: bool = False
    session_id: str = ""
    created_at: str = ""


class TrainingSampleVulnRecord(SQLModel, table=True):
    """Échantillon d'entraînement pour VulnPredictionModel (Phase 2)."""
    __tablename__ = "training_samples_vuln"
    id: str = Field(primary_key=True)
    endpoint_embedding: str = ""  # json.dumps(list[float])
    vuln_labels: str = ""         # json.dumps(dict[str, float])
    session_id: str = ""
    created_at: str = ""


class FindingEmbeddingRecord(SQLModel, table=True):
    """Embedding d'un finding confirmé pour VulnEmbeddingSpace (Phase 5 / Sprint 6)."""
    __tablename__ = "finding_embeddings"
    finding_id: str = Field(primary_key=True)
    embedding: str = ""           # json.dumps(list[float])
    vuln_class: str = ""
    session_id: str = ""
    confidence: float = 1.0       # confiance du finding source (ConfidenceScore.overall)


class PayloadOptimizerStatRecord(SQLModel, table=True):
    """Stats des bras du PayloadOptimizer — persiste les priors inter-sessions (Sprint 4)."""
    __tablename__ = "payload_optimizer_stats"
    fingerprint: str = Field(primary_key=True)   # ex: "POST:1:0:json"
    mutation_type: str = Field(primary_key=True)
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0


class VulnSignatureRecord(SQLModel, table=True):
    """Signatures de vulnérabilités CVE/GHSA récupérées depuis OSV.dev/NVD."""
    __tablename__ = "vuln_signatures"
    vuln_id: str = Field(primary_key=True)   # CVE-2024-XXXXX ou GHSA-xxx-xxx-xxx
    ecosystem: str = ""                       # "PyPI", "npm", "Maven", "RubyGems"
    package: str = ""                         # "django", "express", etc.
    version_range: str = ""                   # ">=3.2,<3.2.15"
    fixed_version: str = ""                   # "3.2.15"
    cvss_score: float = 0.0
    owasp_category: str = ""                  # "A06:2021"
    attack_vector: str = ""                   # indice pour la génération d'hypothèses
    last_fetched: str = ""                    # ISO timestamp
