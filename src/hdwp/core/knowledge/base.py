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

from hdwp.core.knowledge.models import PatternStatsRecord, SessionMetaRecord

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
            await self._migrate_schema(self._engine)
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
                except Exception:
                    pass

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
                total_count = sum(r.total_count for r in records)
                if total_count < MIN_SESSIONS_FOR_TARGET_WEIGHTS:
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
