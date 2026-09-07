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
