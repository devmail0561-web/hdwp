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
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hdwp.core.knowledge.models import PatternStatsRecord, SessionMetaRecord

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding

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
        return self._engine

    async def record_session(
        self,
        findings: list[Finding],
        session_id: str,
        target_url: str,
    ) -> None:
        """Enregistre les résultats d'une session dans la base de connaissances."""
        if not findings:
            return

        engine = await self._get_engine()
        target_hash = _hash_url(target_url)

        async with AsyncSession(engine, expire_on_commit=False) as session:
            for finding in findings:
                property_type = _owasp_to_property_type(finding.owasp_category)
                mutation_type = finding.proof.get("mutation_type", "unknown")

                result = await session.exec(
                    select(PatternStatsRecord).where(
                        PatternStatsRecord.property_type == property_type,
                        PatternStatsRecord.mutation_type == mutation_type,
                    )
                )
                record = result.first()
                if record is None:
                    record = PatternStatsRecord(
                        property_type=property_type,
                        mutation_type=mutation_type,
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

            existing = await session.get(SessionMetaRecord, session_id)
            confirmed_count = len([f for f in findings if f.status == "CONFIRMED"])
            if existing:
                existing.findings_count = confirmed_count
                existing.ended_at = datetime.now(UTC).isoformat()
            else:
                session.add(SessionMetaRecord(
                    session_id=session_id,
                    target_hash=target_hash,
                    findings_count=confirmed_count,
                    ended_at=datetime.now(UTC).isoformat(),
                ))

            await session.commit()

        log.info("knowledge.session_recorded", session_id=session_id, findings=len(findings))

    async def get_adapted_weights(self) -> dict[str, float]:
        """
        Retourne les poids adaptés par l'historique.
        Bootstrap-safe : retourne BASE_WEIGHTS si aucun historique.

        Formule par property_type (agrégé sur tous les mutation_types) :
          confirmed_rate = confirmed / max(total, 1)
          factor = 1.0 + ALPHA * (confirmed_rate - 0.5)
          weight = base * clamp(factor, WEIGHT_MIN/base, WEIGHT_MAX/base)
        """
        engine = await self._get_engine()
        weights = dict(BASE_WEIGHTS)

        async with AsyncSession(engine, expire_on_commit=False) as session:
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

        log.debug("knowledge.weights_adapted", weights=weights)
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
                "confirmed": r.confirmed_count,
                "refuted": r.refuted_count,
                "total": r.total_count,
                "confirmed_rate": round(r.confirmed_count / max(r.total_count, 1), 2),
                "avg_confidence": round(r.avg_confidence, 3),
            }
            for r in records
        ]

    async def get_session_count(self) -> int:
        from sqlalchemy import func
        engine = await self._get_engine()
        async with AsyncSession(engine, expire_on_commit=False) as session:
            result = await session.exec(select(func.count(SessionMetaRecord.session_id)))
            count = result.scalar()
            return count or 0

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
