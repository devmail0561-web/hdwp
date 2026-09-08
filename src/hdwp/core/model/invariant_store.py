# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from hdwp.core.bus.events import INVARIANT_VIOLATED

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

logger = structlog.get_logger()

LEARNING_THRESHOLD = 0.95
MIN_OBSERVATIONS = 5


@dataclass
class LearnedInvariant:
    endpoint_path: str
    pattern_type: str
    formal_statement: str
    observation_count: int = 0
    violation_count: int = 0

    @property
    def confidence(self) -> float:
        if self.observation_count == 0:
            return 0.0
        hold_rate = 1.0 - (self.violation_count / self.observation_count)
        return round(hold_rate, 4)

    @property
    def is_learned(self) -> bool:
        return (
            self.observation_count >= MIN_OBSERVATIONS
            and self.confidence >= LEARNING_THRESHOLD
        )


@dataclass
class InvariantViolation:
    invariant: LearnedInvariant
    experiment_id: str
    observed_value: Any = None
    expected_pattern: str = ""


class InvariantStore:
    def __init__(self, bus: AsyncEventBus | None = None) -> None:
        self._bus = bus
        self._invariants: dict[str, dict[str, LearnedInvariant]] = defaultdict(dict)

    def observe(self, endpoint_path: str, pattern_type: str, holds: bool) -> None:
        key = pattern_type
        inv = self._invariants[endpoint_path].get(key)
        if inv is None:
            inv = LearnedInvariant(
                endpoint_path=endpoint_path,
                pattern_type=pattern_type,
                formal_statement=f"{pattern_type} holds for {endpoint_path}",
            )
            self._invariants[endpoint_path][key] = inv

        inv.observation_count += 1
        if not holds:
            inv.violation_count += 1

    def observe_owner_id_match(
        self,
        endpoint_path: str,
        response_owner_id: Any,
        authenticated_user_id: Any,
    ) -> None:
        holds = response_owner_id == authenticated_user_id
        self.observe(endpoint_path, "owner_id_match", holds)

    def observe_status_code_stable(
        self,
        endpoint_path: str,
        role: str,
        status_code: int,
        expected_code: int,
    ) -> None:
        holds = status_code == expected_code
        self.observe(endpoint_path, f"status_{role}_eq_{expected_code}", holds)

    def observe_field_presence(
        self,
        endpoint_path: str,
        field_name: str,
        present: bool,
        expected: bool = True,
    ) -> None:
        holds = present == expected
        self.observe(endpoint_path, f"field_{field_name}_present", holds)

    async def check_violation(
        self,
        endpoint_path: str,
        pattern_type: str,
        holds: bool,
        experiment_id: str = "",
        observed_value: Any = None,
    ) -> InvariantViolation | None:
        inv = self._invariants.get(endpoint_path, {}).get(pattern_type)
        if inv is None or not inv.is_learned:
            self.observe(endpoint_path, pattern_type, holds)
            return None

        self.observe(endpoint_path, pattern_type, holds)

        if holds:
            return None

        violation = InvariantViolation(
            invariant=inv,
            experiment_id=experiment_id,
            observed_value=observed_value,
            expected_pattern=inv.formal_statement,
        )

        if self._bus:
            await self._bus.emit(
                INVARIANT_VIOLATED,
                {
                    "endpoint_path": endpoint_path,
                    "pattern_type": pattern_type,
                    "formal_statement": inv.formal_statement,
                    "confidence": inv.confidence,
                    "experiment_id": experiment_id,
                    "observed_value": str(observed_value),
                },
                source="invariant_store",
            )
            logger.info(
                "invariant.violated",
                endpoint=endpoint_path,
                pattern=pattern_type,
                confidence=inv.confidence,
            )

        return violation

    async def check_response_violations(
        self,
        endpoint_path: str,
        response_body: object,
        experiment_id: str = "",
    ) -> None:
        """
        Vérifie toutes les violations d'invariants connus pour un endpoint
        contre le corps d'une réponse d'expérience.

        Appelé par SemanticOracle._evaluate_hypothesis sur la réponse de la
        mutation confirmée pour détecter les fuites de données / violations d'accès.
        """
        learned = self.get_learned_invariants(endpoint_path)
        if not learned or not isinstance(response_body, dict):
            return
        for inv in learned:
            pt = inv.pattern_type
            if pt.startswith("field_") and pt.endswith("_present"):
                field_name = pt[6:-8]  # strip "field_" prefix and "_present" suffix
                holds = field_name in response_body
                await self.check_violation(
                    endpoint_path=endpoint_path,
                    pattern_type=pt,
                    holds=holds,
                    experiment_id=experiment_id,
                    observed_value=response_body.get(field_name),
                )

    def get_learned_invariants(self, endpoint_path: str | None = None) -> list[LearnedInvariant]:
        if endpoint_path:
            return [
                inv for inv in self._invariants.get(endpoint_path, {}).values()
                if inv.is_learned
            ]
        return [
            inv
            for ep_invs in self._invariants.values()
            for inv in ep_invs.values()
            if inv.is_learned
        ]

    def all_invariants(self) -> list[LearnedInvariant]:
        return [
            inv
            for ep_invs in self._invariants.values()
            for inv in ep_invs.values()
        ]
