# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
KnowledgeBase: base de connaissances persistante inter-sessions.

Stockée dans ~/.hdwp/knowledge.db (séparé de l'evidence store par session).
Accumule les patterns de vulnérabilités confirmées/réfutées et ajuste
les poids du HypothesisPrioritizer pour les sessions futures.

Apprentissage conservateur (alpha=0.5) :
  - Borne [0.2, 2.0] : aucun type jamais abandonné ni monopolisant
  - Poids statiques inchangés si aucun historique (bootstrap-safe)
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hdwp.core.knowledge.models import (
    FindingEmbeddingRecord,
    PatternStatsRecord,
    PayloadOptimizerStatRecord,
    SessionMetaRecord,
    TrainingSampleOracleRecord,
    TrainingSampleVulnRecord,
)

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, Finding

log = structlog.get_logger()

DEFAULT_KB_PATH = Path.home() / ".hdwp" / "knowledge.db"

BASE_WEIGHTS: dict[str, float] = {
    "authorization": 1.0,
    "confidentiality": 0.9,
    "integrity": 0.8,
    "state": 0.7,
    "coherence": 0.6,
    "temporal": 0.5,
    "concurrency": 0.4,
}

ALPHA = 0.5
WEIGHT_MIN = 0.2
WEIGHT_MAX = 2.0

MIN_SESSIONS_FOR_TARGET_WEIGHTS = 3
MIN_SESSIONS_FOR_CONFIDENCE = 5


def classify_target(
    target_url: str, model_snapshot: ApplicationModelData | None = None
) -> str:
    """Classify target type from URL and optionally from the application model."""
    url = target_url.lower()
    if "/graphql" in url:
        return "graphql"
    if any(seg in url for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/")):
        return "api"
    if not model_snapshot:
        return "unknown"
    paths = [ep.path.lower() for ep in model_snapshot.endpoints]
    if any("wp-" in p or "/admin/" in p or "/cms/" in p for p in paths):
        return "cms"
    json_count = sum(1 for ep in model_snapshot.endpoints if "api" in ep.path.lower())
    if json_count > len(paths) * 0.5:
        return "spa"
    return "unknown"


class KnowledgeBase:
    """Base de connaissances persistante entre sessions de pentest."""

    def __init__(self, db_path: Path | str = DEFAULT_KB_PATH) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._engine: AsyncEngine | None = None

    async def _get_engine(self) -> AsyncEngine:
        if self._engine is None:
            url = f"sqlite+aiosqlite:///{self._db_path}"
            self._engine = create_async_engine(url, echo=False)
            async with self._engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)
            try:
                await self._migrate_schema(self._engine)
            except Exception as _mig_exc:
                log.warning(
                    "knowledge.migration_nonfatal",
                    error=str(_mig_exc),
                    note="engine starts without historical stats",
                )
        return self._engine

    async def _migrate_schema(self, engine: AsyncEngine) -> None:
        """Add missing columns and migrate pattern_stats PK if needed."""
        async with engine.begin() as conn:
            for col, col_type in [
                ("endpoint_count", "INTEGER DEFAULT 0"),
                ("role_count", "INTEGER DEFAULT 0"),
                ("bola_param_count", "INTEGER DEFAULT 0"),
                ("target_type", "TEXT DEFAULT 'unknown'"),
            ]:
                try:
                    await conn.execute(
                        text(f"ALTER TABLE session_meta ADD COLUMN {col} {col_type}")
                    )
                except Exception:
                    pass

            try:
                await conn.execute(text("SELECT target_type FROM pattern_stats LIMIT 1"))
            except Exception:
                try:
                    # Nettoyer une éventuelle table fantôme d'une migration avortée
                    await conn.execute(text("DROP TABLE IF EXISTS pattern_stats_new"))
                    await conn.execute(text("""
                        CREATE TABLE pattern_stats_new (
                            property_type TEXT NOT NULL,
                            mutation_type TEXT NOT NULL,
                            target_type TEXT NOT NULL DEFAULT 'unknown',
                            confirmed_count INTEGER DEFAULT 0,
                            refuted_count INTEGER DEFAULT 0,
                            total_count INTEGER DEFAULT 0,
                            avg_confidence REAL DEFAULT 0.0,
                            last_updated TEXT DEFAULT '',
                            PRIMARY KEY (property_type, mutation_type, target_type)
                        )
                    """))
                    await conn.execute(text("""
                        INSERT INTO pattern_stats_new
                            (property_type, mutation_type, target_type, confirmed_count,
                             refuted_count, total_count, avg_confidence, last_updated)
                        SELECT property_type, mutation_type, 'unknown', confirmed_count,
                               refuted_count, total_count, avg_confidence, last_updated
                        FROM pattern_stats
                    """))
                    await conn.execute(text("DROP TABLE pattern_stats"))
                    await conn.execute(
                        text("ALTER TABLE pattern_stats_new RENAME TO pattern_stats")
                    )
                except Exception as _mig_exc:
                    # Re-raise pour que engine.begin() rollback la transaction entière.
                    # Sans ça, un DROP TABLE réussi + RENAME échoué détruit les stats.
                    log.error(
                        "knowledge.migration_critical",
                        error=str(_mig_exc),
                        note="transaction will rollback — pattern_stats preserved",
                    )
                    raise

            # Table vuln_signatures pour les CVE/GHSA récupérés depuis OSV.dev/NVD
            try:
                await conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS vuln_signatures (
                        vuln_id TEXT PRIMARY KEY,
                        ecosystem TEXT DEFAULT '',
                        package TEXT DEFAULT '',
                        version_range TEXT DEFAULT '',
                        fixed_version TEXT DEFAULT '',
                        cvss_score REAL DEFAULT 0.0,
                        owasp_category TEXT DEFAULT '',
                        attack_vector TEXT DEFAULT '',
                        last_fetched TEXT DEFAULT ''
                    )
                """))
            except Exception:
                pass

            # finding_embeddings.confidence added in sprint 6 — migrate existing DBs
            try:
                await conn.execute(
                    text("ALTER TABLE finding_embeddings ADD COLUMN confidence REAL DEFAULT 1.0")
                )
            except Exception:
                pass

            # ── V4 ML tables ─────────────────────────────────────────────────
            for tbl_sql in [
                """CREATE TABLE IF NOT EXISTS training_samples_oracle (
                    id TEXT PRIMARY KEY,
                    diff_embedding TEXT DEFAULT '',
                    mutation_type TEXT DEFAULT '',
                    verdict TEXT DEFAULT '',
                    human_validated INTEGER DEFAULT 0,
                    session_id TEXT DEFAULT '',
                    created_at TEXT DEFAULT ''
                )""",
                """CREATE TABLE IF NOT EXISTS training_samples_vuln (
                    id TEXT PRIMARY KEY,
                    endpoint_embedding TEXT DEFAULT '',
                    vuln_labels TEXT DEFAULT '',
                    session_id TEXT DEFAULT '',
                    created_at TEXT DEFAULT ''
                )""",
                """CREATE TABLE IF NOT EXISTS finding_embeddings (
                    finding_id TEXT PRIMARY KEY,
                    embedding TEXT DEFAULT '',
                    vuln_class TEXT DEFAULT '',
                    session_id TEXT DEFAULT '',
                    confidence REAL DEFAULT 1.0
                )""",
                """CREATE TABLE IF NOT EXISTS payload_optimizer_stats (
                    fingerprint TEXT NOT NULL,
                    mutation_type TEXT NOT NULL,
                    alpha REAL NOT NULL DEFAULT 1.0,
                    beta REAL NOT NULL DEFAULT 1.0,
                    pulls INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (fingerprint, mutation_type)
                )""",
                """CREATE TABLE IF NOT EXISTS endpoint_clusters (
                    id TEXT PRIMARY KEY,
                    k INTEGER DEFAULT 8,
                    n_samples INTEGER DEFAULT 0,
                    centroids TEXT DEFAULT '',
                    trained_at TEXT DEFAULT ''
                )""",
                """CREATE TABLE IF NOT EXISTS feedback_weights (
                    id TEXT PRIMARY KEY,
                    weights TEXT DEFAULT '',
                    bias REAL DEFAULT -4.0,
                    n_updates INTEGER DEFAULT 0,
                    updated_at TEXT DEFAULT ''
                )""",
                """CREATE TABLE IF NOT EXISTS feedback_weights_history (
                    target_hash TEXT NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'unknown',
                    weights TEXT DEFAULT '',
                    bias REAL DEFAULT -4.0,
                    n_updates INTEGER DEFAULT 0,
                    updated_at TEXT DEFAULT '',
                    PRIMARY KEY (target_hash)
                )""",
            ]:
                try:
                    await conn.execute(text(tbl_sql))
                except Exception:
                    pass

    async def upsert_vuln_signatures(self, sigs: list[dict]) -> int:
        """Persiste des signatures CVE/GHSA dans la knowledge base. Retourne le nombre upserted."""
        from datetime import UTC, datetime

        from hdwp.core.knowledge.models import VulnSignatureRecord

        if not sigs:
            return 0
        now = datetime.now(UTC).isoformat()
        engine = await self._get_engine()
        count = 0
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for sig in sigs:
                rec = VulnSignatureRecord(
                    vuln_id=sig.get("vuln_id", ""),
                    ecosystem=sig.get("ecosystem", ""),
                    package=sig.get("package", ""),
                    version_range=sig.get("version_range", ""),
                    fixed_version=sig.get("fixed_version", ""),
                    cvss_score=float(sig.get("cvss_score", 0.0)),
                    owasp_category=sig.get("owasp_category", ""),
                    attack_vector=sig.get("attack_vector", ""),
                    last_fetched=now,
                )
                try:
                    existing = await session.get(VulnSignatureRecord, rec.vuln_id)
                    if existing:
                        existing.cvss_score = rec.cvss_score
                        existing.fixed_version = rec.fixed_version
                        existing.last_fetched = rec.last_fetched
                        session.add(existing)
                    else:
                        session.add(rec)
                    count += 1
                except Exception:
                    pass
            await session.commit()
        return count

    async def get_signatures_for_package(
        self, package: str, ecosystem: str
    ) -> list[dict]:
        """Retourne les CVE connues pour un package/écosystème donné."""
        from hdwp.core.knowledge.models import VulnSignatureRecord

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(
                select(VulnSignatureRecord).where(
                    VulnSignatureRecord.package == package,
                    VulnSignatureRecord.ecosystem == ecosystem,
                )
            )
            records = result.all()
        return [
            {
                "vuln_id": r.vuln_id,
                "package": r.package,
                "ecosystem": r.ecosystem,
                "version_range": r.version_range,
                "fixed_version": r.fixed_version,
                "cvss_score": r.cvss_score,
                "owasp_category": r.owasp_category,
                "attack_vector": r.attack_vector,
            }
            for r in records
        ]

    async def export_vuln_signatures(self) -> list[dict]:
        """Exporte toutes les signatures CVE pour usage offline."""
        from hdwp.core.knowledge.models import VulnSignatureRecord

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(VulnSignatureRecord))
            records = result.all()
        return [
            {
                "vuln_id": r.vuln_id, "ecosystem": r.ecosystem, "package": r.package,
                "version_range": r.version_range, "fixed_version": r.fixed_version,
                "cvss_score": r.cvss_score, "owasp_category": r.owasp_category,
                "attack_vector": r.attack_vector, "last_fetched": r.last_fetched,
            }
            for r in records
        ]

    async def record_session(
        self,
        findings: list[Finding],
        session_id: str,
        target_url: str,
        model_snapshot: ApplicationModelData | None = None,
    ) -> None:
        """Enregistre les résultats d'une session dans la base de connaissances."""
        if not findings:
            return

        engine = await self._get_engine()
        target_hash = _hash_url(target_url)
        target_type = classify_target(target_url, model_snapshot)

        async with AsyncSession(engine, expire_on_commit=False) as session:
            for finding in findings:
                property_type = _owasp_to_property_type(finding.owasp_category)
                mutation_type = finding.proof.get("mutation_type", "unknown")

                result = await session.exec(
                    select(PatternStatsRecord).where(
                        PatternStatsRecord.property_type == property_type,
                        PatternStatsRecord.mutation_type == mutation_type,
                        PatternStatsRecord.target_type == target_type,
                    )
                )
                record = result.first()
                if record is None:
                    record = PatternStatsRecord(
                        property_type=property_type,
                        mutation_type=mutation_type,
                        target_type=target_type,
                    )
                    session.add(record)

                record.total_count += 1
                if finding.status == "CONFIRMED":
                    record.confirmed_count += 1
                    n = record.confirmed_count
                    record.avg_confidence = (
                        record.avg_confidence * (n - 1) + finding.confidence
                    ) / n
                else:
                    record.refuted_count += 1
                record.last_updated = datetime.now(UTC).isoformat()

            endpoint_count = len(model_snapshot.endpoints) if model_snapshot else 0
            role_count = len(model_snapshot.roles) if model_snapshot else 0
            bola_param_count = (
                sum(1 for p in model_snapshot.parameters if p.affects_object)
                if model_snapshot
                else 0
            )

            existing = await session.get(SessionMetaRecord, session_id)
            confirmed_count = len([f for f in findings if f.status == "CONFIRMED"])
            now = datetime.now(UTC).isoformat()
            if existing:
                existing.findings_count = confirmed_count
                existing.ended_at = now
                existing.endpoint_count = endpoint_count
                existing.role_count = role_count
                existing.bola_param_count = bola_param_count
                existing.target_type = target_type
            else:
                session.add(SessionMetaRecord(
                    session_id=session_id,
                    target_hash=target_hash,
                    findings_count=confirmed_count,
                    ended_at=now,
                    endpoint_count=endpoint_count,
                    role_count=role_count,
                    bola_param_count=bola_param_count,
                    target_type=target_type,
                ))

            await session.commit()

        log.info("knowledge.session_recorded", session_id=session_id, findings=len(findings))

    async def get_adapted_weights(
        self, target_type: str | None = None
    ) -> dict[str, float]:
        """
        Retourne les poids adaptés par l'historique.
        Bootstrap-safe : retourne BASE_WEIGHTS si aucun historique.

        Si target_type est fourni et qu'il y a assez de données pour ce type,
        utilise uniquement les stats de ce type. Sinon fallback sur global.
        """
        engine = await self._get_engine()
        weights = dict(BASE_WEIGHTS)

        async with AsyncSession(engine, expire_on_commit=False) as session:
            if target_type:
                result = await session.exec(
                    select(PatternStatsRecord).where(
                        PatternStatsRecord.target_type == target_type
                    )
                )
                records = result.all()
                # Count distinct sessions for this target_type so that the
                # threshold is compared against session count, not experiment
                # count.  Using total_count (experiments) incorrectly activates
                # target-specific weights after a single session with >= 3 runs.
                from sqlalchemy import func
                from sqlalchemy import select as sql_select
                stmt = sql_select(func.count()).select_from(SessionMetaRecord).where(
                    SessionMetaRecord.target_type == target_type
                )
                # Use raw session.execute for aggregate scalar queries.
                count_result = await session.execute(stmt)
                session_count_for_type = int(count_result.scalar() or 0)
                if session_count_for_type < MIN_SESSIONS_FOR_TARGET_WEIGHTS:
                    result = await session.exec(select(PatternStatsRecord))
                    records = result.all()
            else:
                result = await session.exec(select(PatternStatsRecord))
                records = result.all()

        if not records:
            return weights

        aggregated: dict[str, dict[str, float]] = {}
        for rec in records:
            pt = rec.property_type
            if pt not in aggregated:
                aggregated[pt] = {"confirmed": 0.0, "total": 0.0}
            aggregated[pt]["confirmed"] += rec.confirmed_count
            aggregated[pt]["total"] += rec.total_count

        for pt, counts in aggregated.items():
            if counts["total"] == 0:
                continue
            confirmed_rate = counts["confirmed"] / counts["total"]
            factor = 1.0 + ALPHA * (confirmed_rate - 0.5)
            base = BASE_WEIGHTS.get(pt, 0.5)
            lo = WEIGHT_MIN / base
            hi = WEIGHT_MAX / base
            factor = max(lo, min(hi, factor))
            weights[pt] = round(base * factor, 4)

        log.debug("knowledge.weights_adapted", weights=weights, target_type=target_type)
        return weights

    async def get_stats(self) -> list[dict[str, Any]]:
        """Retourne les stats pour affichage CLI."""
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(
                select(PatternStatsRecord).order_by(
                    PatternStatsRecord.confirmed_count.desc()  # type: ignore[attr-defined]
                )
            )
            records = result.all()

        return [
            {
                "property_type": r.property_type,
                "mutation_type": r.mutation_type,
                "target_type": r.target_type,
                "confirmed": r.confirmed_count,
                "refuted": r.refuted_count,
                "total": r.total_count,
                "confirmed_rate": round(r.confirmed_count / max(r.total_count, 1), 2),
                "avg_confidence": round(r.avg_confidence, 3),
            }
            for r in records
        ]

    async def get_confidence_weights(self) -> dict[str, float]:
        """Compute adaptive model_confidence weights from session history."""
        defaults = {"ep": 0.4, "role": 0.4, "bola": 0.2}
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.execute(text("""
                SELECT
                    COUNT(*) as n,
                    AVG(CASE WHEN endpoint_count > 0
                        THEN CAST(findings_count AS REAL) / endpoint_count ELSE NULL END) as ep_ratio,
                    AVG(CASE WHEN role_count > 0
                        THEN CAST(findings_count AS REAL) / role_count ELSE NULL END) as role_ratio,
                    AVG(CASE WHEN bola_param_count > 0
                        THEN CAST(findings_count AS REAL) / bola_param_count ELSE NULL END) as bola_ratio
                FROM session_meta
                WHERE findings_count > 0 AND endpoint_count > 0
            """))
            row = result.one()

        if row.n < MIN_SESSIONS_FOR_CONFIDENCE:
            return defaults

        ep = row.ep_ratio or 0
        role = row.role_ratio or 0
        bola = row.bola_ratio or 0
        total = ep + role + bola
        if total == 0:
            return defaults

        raw = {"ep": ep / total, "role": role / total, "bola": bola / total}
        return {k: round(max(0.1, min(0.7, v)), 4) for k, v in raw.items()}

    async def get_session_count(self) -> int:
        from sqlalchemy import func
        from sqlalchemy import select as sql_select
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            stmt = sql_select(func.count()).select_from(SessionMetaRecord)
            result = await session.execute(stmt)
            count = result.scalar()
            return int(count) if count is not None else 0

    async def reset(self) -> None:
        """Réinitialise pattern_stats (garde session_meta pour l'historique)."""
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(PatternStatsRecord))
            for rec in result.all():
                await session.delete(rec)
            await session.commit()
        log.info("knowledge.reset")

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()
            self._engine = None

    # ── V4 ML data collection ────────────────────────────────────────────────

    async def store_oracle_sample(
        self,
        diff_embedding: list[float],
        mutation_type: str,
        verdict: str,
        session_id: str,
        human_validated: bool = False,
    ) -> None:
        """Persiste un échantillon d'entraînement pour l'OracleModel."""
        import json

        from hdwp.core.model.schemas import generate_id

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            rec = TrainingSampleOracleRecord(
                id=generate_id("OTRN"),
                diff_embedding=json.dumps(diff_embedding),
                mutation_type=mutation_type,
                verdict=verdict,
                human_validated=human_validated,
                session_id=session_id,
                created_at=datetime.now(UTC).isoformat(),
            )
            session.add(rec)
            await session.commit()

    async def store_vuln_sample(
        self,
        endpoint_embedding: list[float],
        vuln_labels: dict[str, float],
        session_id: str,
    ) -> None:
        """Persiste un échantillon d'entraînement pour VulnPredictionModel."""
        import json

        from hdwp.core.model.schemas import generate_id

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            rec = TrainingSampleVulnRecord(
                id=generate_id("VTRN"),
                endpoint_embedding=json.dumps(endpoint_embedding),
                vuln_labels=json.dumps(vuln_labels),
                session_id=session_id,
                created_at=datetime.now(UTC).isoformat(),
            )
            session.add(rec)
            await session.commit()

    async def get_finding_embeddings(self) -> list[dict[str, Any]]:
        """Retourne tous les embeddings de findings confirmés pour le SimilarityIndex."""
        import json

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(FindingEmbeddingRecord))
            records = result.all()
        return [
            {
                "finding_id": r.finding_id,
                "embedding": json.loads(r.embedding) if r.embedding else [],
                "vuln_class": r.vuln_class,
                "session_id": r.session_id,
                "confidence": r.confidence,
            }
            for r in records
            if r.embedding
        ]

    async def store_finding_embedding(
        self,
        finding_id: str,
        embedding: list[float],
        vuln_class: str,
        session_id: str,
        confidence: float = 1.0,
    ) -> None:
        """Persiste l'embedding d'un finding confirmé pour VulnEmbeddingSpace."""
        import json

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            rec = FindingEmbeddingRecord(
                finding_id=finding_id,
                embedding=json.dumps(embedding),
                vuln_class=vuln_class,
                session_id=session_id,
                confidence=confidence,
            )
            # Upsert : remplace si finding_id existe déjà
            existing = await session.get(FindingEmbeddingRecord, finding_id)
            if existing:
                existing.embedding = rec.embedding
                existing.vuln_class = rec.vuln_class
                existing.confidence = rec.confidence
                session.add(existing)
            else:
                session.add(rec)
            await session.commit()

    async def store_cluster_centroids(
        self,
        centroids: list[list[float]],
        k: int,
        n_samples: int,
    ) -> None:
        """Persiste les centroïdes du EndpointClusterer (upsert sur id='current')."""
        import json
        from datetime import UTC, datetime

        engine = await self._get_engine()
        async with engine.begin() as conn:
            now = datetime.now(UTC).isoformat()
            await conn.execute(
                text("""
                    INSERT INTO endpoint_clusters (id, k, n_samples, centroids, trained_at)
                    VALUES ('current', :k, :n, :c, :ts)
                    ON CONFLICT(id) DO UPDATE SET
                        k=excluded.k, n_samples=excluded.n_samples,
                        centroids=excluded.centroids, trained_at=excluded.trained_at
                """),
                {"k": k, "n": n_samples, "c": json.dumps(centroids), "ts": now},
            )

    async def get_cluster_centroids(self) -> dict | None:
        """Retourne les données de clustering persistées, ou None si absentes."""
        import json

        engine = await self._get_engine()
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT k, n_samples, centroids, trained_at FROM endpoint_clusters WHERE id='current'")
            )
            row = result.fetchone()
            if row is None:
                return None
            centroids_raw = row[2]
            if not centroids_raw:
                return None
            try:
                centroids = json.loads(centroids_raw)
            except Exception:
                return None
            return {
                "k": row[0],
                "n_samples": row[1],
                "centroids": centroids,
                "trained_at": row[3],
            }

    async def store_feedback_weights(self, data: dict) -> None:
        """Persiste les poids FeedbackLoop (upsert sur id='current')."""
        import json
        from datetime import UTC, datetime

        engine = await self._get_engine()
        async with engine.begin() as conn:
            now = datetime.now(UTC).isoformat()
            await conn.execute(
                text("""
                    INSERT INTO feedback_weights (id, weights, bias, n_updates, updated_at)
                    VALUES ('current', :w, :b, :n, :ts)
                    ON CONFLICT(id) DO UPDATE SET
                        weights=excluded.weights, bias=excluded.bias,
                        n_updates=excluded.n_updates, updated_at=excluded.updated_at
                """),
                {
                    "w": json.dumps(data.get("weights", {})),
                    "b": float(data.get("bias", -4.0)),
                    "n": int(data.get("n_updates", 0)),
                    "ts": now,
                },
            )

    async def get_feedback_weights(self) -> dict | None:
        """Retourne les poids FeedbackLoop persistés, ou None si absents."""
        import json

        engine = await self._get_engine()
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT weights, bias, n_updates FROM feedback_weights WHERE id='current'")
            )
            row = result.fetchone()
            if row is None:
                return None
            try:
                weights = json.loads(row[0]) if row[0] else {}
            except Exception:
                return None
            return {"weights": weights, "bias": row[1], "n_updates": row[2]}

    async def get_oracle_training_data(
        self, only_validated: bool = True
    ) -> list[dict[str, Any]]:
        """Retourne les échantillons oracle, avec désérialisation des embeddings."""
        import json

        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            stmt = select(TrainingSampleOracleRecord)
            if only_validated:
                stmt = stmt.where(TrainingSampleOracleRecord.human_validated == True)  # noqa: E712
            result = await session.exec(stmt)
            records = result.all()

        return [
            {
                "id": r.id,
                "diff_embedding": json.loads(r.diff_embedding) if r.diff_embedding else [],
                "mutation_type": r.mutation_type,
                "verdict": r.verdict,
                "human_validated": bool(r.human_validated),
                "session_id": r.session_id,
                "created_at": r.created_at,
            }
            for r in records
        ]

    async def get_vuln_training_data(
        self, only_validated: bool = True
    ) -> list[dict[str, Any]]:
        """Retourne les échantillons vuln, avec désérialisation des embeddings."""
        import json

        # Pour l'instant, training_samples_vuln ne contient pas de flag human_validated.
        # only_validated est ignoré — prévu pour Sprint 2 quand l'interface UI sera disponible.
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(TrainingSampleVulnRecord))
            records = result.all()

        return [
            {
                "id": r.id,
                "endpoint_embedding": json.loads(r.endpoint_embedding) if r.endpoint_embedding else [],
                "vuln_labels": json.loads(r.vuln_labels) if r.vuln_labels else {},
                "session_id": r.session_id,
                "created_at": r.created_at,
            }
            for r in records
        ]

    async def store_oracle_samples_from_session(
        self,
        session_id: str,
        oracle_results: dict[str, list[Any]],
        findings: list[Any],
        embedder: Any,
    ) -> int:
        """
        Calcule et persiste les DiffEmbeddings depuis les résultats d'une session.

        Pour chaque finding, identifie la baseline (replayed_from=None, mutation_params={})
        et calcule un embedding pour chaque mutation (replayed_from=None, mutation_params!={}).

        Retourne le nombre de samples stockés.
        """
        count = 0
        for finding in findings:
            hyp_id = finding.hypothesis_id
            results = oracle_results.get(hyp_id, [])
            if not results:
                continue

            # Baseline : identifiée par le flag is_baseline (ExperimentEngine le pose au moment
            # de la création). Fallback sur results[0] pour les enregistrements antérieurs.
            baseline = next(
                (r for r in results if getattr(r, "is_baseline", False)),
                results[0],
            )

            # Mutations : tous les résultats non-replay et non-baseline
            mutations = [
                r for r in results
                if not getattr(r, "is_baseline", False) and r.replayed_from is None
            ]

            verdict = finding.status  # "CONFIRMED" | "REFUTED"
            mutation_type = baseline.experiment_spec.mutation_type

            for mut in mutations:
                try:
                    emb = embedder.embed(
                        baseline.response_received,
                        mut.response_received,
                    )
                    await self.store_oracle_sample(
                        diff_embedding=emb,
                        mutation_type=mutation_type,
                        verdict=verdict,
                        session_id=session_id,
                    )
                    count += 1
                except Exception as exc:
                    log.warning(
                        "kb.store_oracle_sample_failed",
                        hypothesis_id=hyp_id,
                        error=str(exc),
                    )

        return count

    async def count_oracle_training_data(self, only_validated: bool = False) -> int:
        """Retourne le nombre de samples oracle via SELECT COUNT(*) scalaire."""
        from sqlalchemy import func as _func
        from sqlalchemy import select as _sql_select
        engine = await self._get_engine()
        async with engine.connect() as conn:
            stmt = _sql_select(_func.count()).select_from(TrainingSampleOracleRecord)
            if only_validated:
                stmt = stmt.where(TrainingSampleOracleRecord.human_validated == True)  # noqa: E712
            result = await conn.execute(stmt)
            return result.scalar() or 0

    async def count_vuln_training_data(self) -> int:
        """Retourne le nombre de samples vuln via SELECT COUNT(*) scalaire."""
        from sqlalchemy import func as _func
        from sqlalchemy import select as _sql_select
        engine = await self._get_engine()
        async with engine.connect() as conn:
            stmt = _sql_select(_func.count()).select_from(TrainingSampleVulnRecord)
            result = await conn.execute(stmt)
            return result.scalar() or 0

    async def get_payload_optimizer_stats(self) -> list[dict[str, Any]]:
        """Retourne les stats des bras du PayloadOptimizer pour la session courante."""
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(PayloadOptimizerStatRecord))
            records = result.all()
        return [
            {
                "fingerprint": r.fingerprint,
                "mutation_type": r.mutation_type,
                "alpha": r.alpha,
                "beta": r.beta,
                "pulls": r.pulls,
            }
            for r in records
        ]

    async def save_payload_optimizer_stats(self, stats: list[dict[str, Any]]) -> None:
        """Upsert les stats des bras du PayloadOptimizer dans la KB."""
        if not stats:
            return
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for s in stats:
                fp = s.get("fingerprint", "")
                mt = s.get("mutation_type", "")
                if not fp or not mt:
                    continue
                existing = await session.get(PayloadOptimizerStatRecord, (fp, mt))
                if existing:
                    existing.alpha = float(s.get("alpha", existing.alpha))
                    existing.beta = float(s.get("beta", existing.beta))
                    existing.pulls = int(s.get("pulls", existing.pulls))
                    session.add(existing)
                else:
                    session.add(PayloadOptimizerStatRecord(
                        fingerprint=fp,
                        mutation_type=mt,
                        alpha=float(s.get("alpha", 1.0)),
                        beta=float(s.get("beta", 1.0)),
                        pulls=int(s.get("pulls", 0)),
                    ))
            await session.commit()
        log.info("kb.payload_optimizer_stats_saved", count=len(stats))

    async def train_vuln_model(
        self,
        model: Any,
    ) -> Any:
        """
        Entraîne le VulnClassifier sur les données accumulées.

        Args:
            model: instance VulnClassifier

        Retourne un VulnTrainingResult (ou None si pas assez de données).
        """
        samples = await self.get_vuln_training_data(only_validated=False)
        if not samples:
            log.info("kb.train_vuln_model.no_samples")
            return None
        result = model.train(samples)
        if result.trained:
            model.save()
            log.info(
                "kb.vuln_model_trained",
                n_samples=result.n_samples,
                vuln_types=result.vuln_types_trained,
            )
        else:
            log.info("kb.train_vuln_model.skipped", reason=result.error)
        return result

    async def train_oracle_model(
        self,
        model: Any,
        only_validated: bool = False,
    ) -> Any:
        """
        Entraîne l'OracleModel sur les données accumulées.

        Args:
            model: instance OracleModel
            only_validated: si True, utilise uniquement les samples human_validated

        Retourne un TrainingResult (ou None si pas assez de données).
        """
        samples = await self.get_oracle_training_data(only_validated=only_validated)
        if not samples:
            log.info("kb.train_oracle_model.no_samples")
            return None
        result = model.train(samples)
        if result.trained:
            model.save()
            log.info(
                "kb.oracle_model_trained",
                n_samples=result.n_samples,
                val_accuracy=round(result.val_accuracy, 3),
            )
        else:
            log.info("kb.train_oracle_model.skipped", reason=result.error)
        return result


    async def store_feedback_weights_for_target(
        self, target_hash: str, target_type: str, data: dict
    ) -> None:
        """Persiste les poids FeedbackLoop d'un target spécifique (upsert sur target_hash)."""
        import json

        engine = await self._get_engine()
        async with engine.begin() as conn:
            now = datetime.now(UTC).isoformat()
            await conn.execute(
                text("""
                    INSERT INTO feedback_weights_history
                        (target_hash, target_type, weights, bias, n_updates, updated_at)
                    VALUES (:th, :tt, :w, :b, :n, :ts)
                    ON CONFLICT(target_hash) DO UPDATE SET
                        target_type=excluded.target_type,
                        weights=excluded.weights,
                        bias=excluded.bias,
                        n_updates=excluded.n_updates,
                        updated_at=excluded.updated_at
                """),
                {
                    "th": target_hash,
                    "tt": target_type,
                    "w": json.dumps(data.get("weights", {})),
                    "b": float(data.get("bias", -4.0)),
                    "n": int(data.get("n_updates", 0)),
                    "ts": now,
                },
            )

    async def get_feedback_weights_for_target(self, target_hash: str) -> dict | None:
        """Retourne les poids FeedbackLoop persistés pour un target donné, ou None."""
        import json

        engine = await self._get_engine()
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT weights, bias, n_updates, target_type "
                    "FROM feedback_weights_history WHERE target_hash=:th"
                ),
                {"th": target_hash},
            )
            row = result.fetchone()
            if row is None:
                return None
            try:
                weights = json.loads(row[0]) if row[0] else {}
            except Exception:
                return None
            return {
                "weights": weights,
                "bias": row[1],
                "n_updates": row[2],
                "target_type": row[3],
                "target_hash": target_hash,
            }

    async def list_feedback_weights_snapshots(self) -> list[dict]:
        """Retourne tous les snapshots de poids FeedbackLoop par target."""
        import json

        engine = await self._get_engine()
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT target_hash, target_type, weights, bias, n_updates "
                    "FROM feedback_weights_history ORDER BY n_updates DESC"
                )
            )
            rows = result.fetchall()
        snapshots = []
        for row in rows:
            try:
                weights = json.loads(row[2]) if row[2] else {}
            except Exception:
                continue
            snapshots.append({
                "target_hash": row[0],
                "target_type": row[1],
                "weights": weights,
                "bias": row[3],
                "n_updates": row[4],
            })
        return snapshots


def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:8]


def _owasp_to_property_type(owasp: str) -> str:
    mapping = {
        "A01:2021": "authorization",
        "A02:2021": "confidentiality",
        "A03:2021": "integrity",
        "A04:2021": "concurrency",
        "A05:2021": "coherence",
        "A06:2021": "integrity",
        "A07:2021": "authorization",
        "A08:2021": "integrity",
        "A09:2021": "coherence",
        "A10:2021": "integrity",
    }
    result = mapping.get(owasp)
    if result is None:
        if owasp:
            log.debug("knowledge.unknown_owasp", owasp=owasp, fallback="integrity")
        return "integrity"
    return result
