# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlmodel import select

from hdwp.store.credential_filter import filter_credentials
from hdwp.store.models import (
    DiffRecord,
    ExperimentRecord,
    FindingRecord,
    HypothesisRecord,
    ModelSnapshotRecord,
    ObservationRecord,
    PropertyRecord,
)

if TYPE_CHECKING:
    from hdwp.core.model.schemas import (
        ExperimentResult,
        Finding,
        Hypothesis,
        RawObservation,
        SecurityProperty,
        SemanticDiff,
    )


class Repository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def _session(self) -> AsyncSession:
        return AsyncSession(self._engine, expire_on_commit=False)

    # ── observations ──────────────────────────────────────────

    async def save_observation(self, obs: RawObservation) -> None:
        data = json.loads(obs.model_dump_json())
        data = filter_credentials(data)
        record = ObservationRecord(
            id=obs.id,
            timestamp=obs.timestamp,
            source=obs.source,
            type=obs.type.value if hasattr(obs.type, "value") else str(obs.type),
            session_id=obs.session_id,
            data_json=json.dumps(data),
        )
        async with await self._session() as session:
            session.add(record)
            await session.commit()

    async def get_observation(self, id: str) -> RawObservation | None:
        from hdwp.core.model.schemas import RawObservation

        async with await self._session() as session:
            record = await session.get(ObservationRecord, id)
            if record is None:
                return None
            return RawObservation.model_validate_json(record.data_json)

    # ── properties ────────────────────────────────────────────

    async def save_property(self, prop: SecurityProperty) -> None:
        record = PropertyRecord(
            id=prop.id,
            type=prop.type.value if hasattr(prop.type, "value") else str(prop.type),
            status=prop.status,
            inference_confidence=prop.inference_confidence,
            data_json=prop.model_dump_json(),
        )
        async with await self._session() as session:
            session.add(record)
            await session.commit()

    # ── hypotheses ────────────────────────────────────────────

    async def save_hypothesis(self, hyp: Hypothesis) -> None:
        record = HypothesisRecord(
            id=hyp.id,
            property_id=hyp.property_id,
            status=hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
            priority=hyp.priority,
            source_plugin=hyp.source_plugin,
            confidence=hyp.confidence,
            data_json=hyp.model_dump_json(),
        )
        async with await self._session() as session:
            session.add(record)
            await session.commit()

    async def get_hypothesis(self, id: str) -> Hypothesis | None:
        from hdwp.core.model.schemas import Hypothesis

        async with await self._session() as session:
            record = await session.get(HypothesisRecord, id)
            if record is None:
                return None
            return Hypothesis.model_validate_json(record.data_json)

    async def list_hypotheses(self, status: str | None = None) -> list[Hypothesis]:
        from hdwp.core.model.schemas import Hypothesis

        async with await self._session() as session:
            stmt = select(HypothesisRecord)
            if status is not None:
                stmt = stmt.where(HypothesisRecord.status == status)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [Hypothesis.model_validate_json(r.data_json) for r in rows]

    async def update_hypothesis_status(
        self, id: str, status: str, confidence: float
    ) -> None:
        from hdwp.core.model.schemas import Hypothesis

        async with await self._session() as session:
            record = await session.get(HypothesisRecord, id)
            if record is None:
                return
            record.status = status
            record.confidence = confidence
            record.updated_at = datetime.now(UTC).isoformat()
            from hdwp.core.model.schemas import HypothesisStatus as HS

            hyp = Hypothesis.model_validate_json(record.data_json)
            hyp.status = HS(status)
            hyp.confidence = confidence
            record.data_json = hyp.model_dump_json()
            session.add(record)
            await session.commit()

    # ── experiments ───────────────────────────────────────────

    async def save_experiment(self, exp: ExperimentResult) -> None:
        record = ExperimentRecord(
            id=exp.id,
            hypothesis_id=exp.hypothesis_id,
            timing_ms=exp.timing_ms,
            data_json=exp.model_dump_json(),
        )
        async with await self._session() as session:
            session.add(record)
            await session.commit()

    # ── diffs ─────────────────────────────────────────────────

    async def save_diff(self, diff: SemanticDiff) -> None:
        record = DiffRecord(
            id=diff.id,
            exp_a=diff.exp_a,
            exp_b=diff.exp_b,
            verdict=diff.verdict.value if hasattr(diff.verdict, "value") else str(diff.verdict),
            data_json=diff.model_dump_json(),
        )
        async with await self._session() as session:
            session.add(record)
            await session.commit()

    # ── findings ──────────────────────────────────────────────

    async def save_finding(self, finding: Finding) -> None:
        record = FindingRecord(
            id=finding.id,
            hypothesis_id=finding.hypothesis_id,
            property_id=finding.property_id,
            status=finding.status,
            severity=finding.severity,
            owasp_category=finding.owasp_category,
            cwe_id=finding.cwe_id,
            confidence=finding.confidence,
            data_json=finding.model_dump_json(),
        )
        async with await self._session() as session:
            existing = await session.get(FindingRecord, finding.id)
            if existing:
                for key, value in record.__dict__.items():
                    if not key.startswith("_"):
                        setattr(existing, key, value)
                session.add(existing)
            else:
                session.add(record)
            await session.commit()

    async def get_finding(self, id: str) -> Finding | None:
        from hdwp.core.model.schemas import Finding

        async with await self._session() as session:
            record = await session.get(FindingRecord, id)
            if record is None:
                return None
            return Finding.model_validate_json(record.data_json)

    async def list_findings(self, status: str | None = None) -> list[Finding]:
        from hdwp.core.model.schemas import Finding

        async with await self._session() as session:
            stmt = select(FindingRecord)
            if status is not None:
                stmt = stmt.where(FindingRecord.status == status)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [Finding.model_validate_json(r.data_json) for r in rows]

    # ── model snapshots ───────────────────────────────────────

    async def save_model_snapshot(self, snapshot_id: str, data_json: str) -> None:
        record = ModelSnapshotRecord(id=snapshot_id, data_json=data_json)
        async with await self._session() as session:
            session.add(record)
            await session.commit()
