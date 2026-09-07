# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hdwp.core.attack_graph.state import AttackState, AttackTransition
from hdwp.core.bus.events import HYPOTHESIS_GENERATED, PRECONDITION_MISSING
from hdwp.core.model.schemas import ExperimentSpec, Hypothesis, NormalizedRequest

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

logger = structlog.get_logger()


class PreconditionSolver:
    def __init__(self, bus: AsyncEventBus) -> None:
        self._bus = bus

    async def solve(
        self,
        state: AttackState,
        transition: AttackTransition,
    ) -> list[Hypothesis]:
        missing: dict[str, set[str]] = {}
        for key, required in transition.preconditions.items():
            current = getattr(state, key, set())
            if isinstance(current, set):
                diff = required - current
                if diff:
                    missing[key] = diff

        if not missing:
            return []

        await self._bus.emit(
            PRECONDITION_MISSING,
            {
                "finding_id": transition.finding_id,
                "missing": {k: list(v) for k, v in missing.items()},
                "endpoint": transition.endpoint,
            },
            source="precondition_solver",
        )

        hypotheses: list[Hypothesis] = []
        for key, needed in missing.items():
            for item in needed:
                hyp = Hypothesis(
                    source_plugin="precondition_solver",
                    property_id=f"PRECOND-{transition.finding_id[:8]}",
                    statement=f"Precondition: acquire {key}={item} for {transition.endpoint}",
                    property_type="precondition",
                    priority="HIGH",
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="precondition_probe",
                            base_request=NormalizedRequest(
                                method="GET", url=transition.endpoint
                            ),
                            mutation_params={
                                "target_capability": key,
                                "target_value": item,
                                "parent_finding_id": transition.finding_id,
                            },
                        )
                    ],
                )
                hypotheses.append(hyp)

                await self._bus.emit(
                    HYPOTHESIS_GENERATED,
                    hyp.model_dump(),
                    source="precondition_solver",
                )

        return hypotheses
