# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import structlog
from typing import Any, Callable, TYPE_CHECKING

from hdwp.core.bus.events import (
    FLOW_UPDATED,
    HDWPEvent,
    MODEL_UPDATED,
    THREAT_MODEL_UPDATED,
)
from hdwp.core.threat.asset_registry import AssetRegistry
from hdwp.core.threat.scorer import AttackSurfaceScorer

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.model.schemas import ApplicationModelData, DataFlowMap

logger = structlog.get_logger()


class ThreatModelEngine:
    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable[[], ApplicationModelData | None],
        flow_map_accessor: Callable[[], DataFlowMap | None],
    ) -> None:
        self._bus = bus
        self._model_accessor = model_accessor
        self._flow_map_accessor = flow_map_accessor
        self._registry = AssetRegistry()
        self._scorer = AttackSurfaceScorer(self._registry)
        self._scores: dict[str, float] = {}
        self._classifications: dict[str, str] = {}

        bus.on(MODEL_UPDATED, self._on_model_updated)
        bus.on(FLOW_UPDATED, self._on_flow_updated)

    async def _on_model_updated(self, event: HDWPEvent) -> None:
        await self._recompute()

    async def _on_flow_updated(self, event: HDWPEvent) -> None:
        await self._recompute()

    async def _recompute(self) -> None:
        model = self._model_accessor()
        if not model or not model.endpoints:
            return

        flow_map = self._flow_map_accessor()
        classifications = self._registry.classify_all(model)
        scores = self._scorer.score_all(model, flow_map)

        if scores != self._scores:
            self._scores = scores
            self._classifications = {k: v.value for k, v in classifications.items()}

            await self._bus.emit(HDWPEvent(
                type=THREAT_MODEL_UPDATED,
                source="threat_model_engine",
                payload={
                    "scores": self._scores,
                    "classifications": self._classifications,
                },
            ))
            logger.info(
                "threat_model.updated",
                n_endpoints=len(scores),
                max_score=max(scores.values()) if scores else 0,
            )

    @property
    def scores(self) -> dict[str, float]:
        return dict(self._scores)

    @property
    def classifications(self) -> dict[str, str]:
        return dict(self._classifications)

    def get_score(self, endpoint_path: str) -> float:
        return self._scores.get(endpoint_path, 0.0)
