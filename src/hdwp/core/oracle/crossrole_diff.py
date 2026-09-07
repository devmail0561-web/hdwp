# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import structlog
from collections import defaultdict
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

from hdwp.core.bus.events import (
    CROSSROLE_DIFF_CONFIRMED,
    EXPERIMENT_RESULT,
    HDWPEvent,
)

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.model.schemas import ApplicationModelData

logger = structlog.get_logger()


class DiffType(str, Enum):
    STRUCTURAL = "STRUCTURAL"
    VALUE = "VALUE"
    IDENTITY = "IDENTITY"


class CrossRoleDiffResult:
    __slots__ = ("endpoint_path", "diff_type", "details", "confidence")

    def __init__(
        self,
        endpoint_path: str,
        diff_type: DiffType,
        details: dict[str, Any],
        confidence: float = 0.8,
    ) -> None:
        self.endpoint_path = endpoint_path
        self.diff_type = diff_type
        self.details = details
        self.confidence = confidence


_IDENTITY_FIELDS = frozenset({
    "id", "user_id", "owner_id", "account_id", "author_id",
    "creator_id", "customer_id", "member_id",
})

_SENSITIVE_FIELDS = frozenset({
    "password", "token", "secret", "api_key", "ssn",
    "credit_card", "balance", "salary", "internal_notes",
})


class CrossRoleDiffEngine:
    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable[[], ApplicationModelData | None] | None = None,
    ) -> None:
        self._bus = bus
        self._model_accessor = model_accessor
        self._corpus: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
            lambda: defaultdict(list)
        )

        bus.on(EXPERIMENT_RESULT, self._on_experiment_result)

    async def _on_experiment_result(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        response = payload.get("response_received") or {}
        body = response.get("body")
        if not isinstance(body, dict):
            return

        request = payload.get("request_sent") or {}
        url = request.get("url", "")
        role = payload.get("replayed_from", "unknown")

        if url and role:
            self._corpus[url][role].append(body)
            await self._try_diff(url)

    async def _try_diff(self, endpoint_path: str) -> None:
        role_bodies = self._corpus.get(endpoint_path, {})
        if len(role_bodies) < 2:
            return

        roles = list(role_bodies.keys())
        for i, role_a in enumerate(roles):
            for role_b in roles[i + 1:]:
                bodies_a = role_bodies[role_a]
                bodies_b = role_bodies[role_b]
                if not bodies_a or not bodies_b:
                    continue
                diffs = self._compare(endpoint_path, role_a, bodies_a[-1], role_b, bodies_b[-1])
                for diff in diffs:
                    await self._bus.emit(HDWPEvent(
                        type=CROSSROLE_DIFF_CONFIRMED,
                        source="crossrole_diff_engine",
                        payload={
                            "endpoint_path": diff.endpoint_path,
                            "diff_type": diff.diff_type.value,
                            "role_a": role_a,
                            "role_b": role_b,
                            "confidence": diff.confidence,
                            "details": diff.details,
                        },
                    ))

    def _compare(
        self,
        endpoint_path: str,
        role_a: str,
        body_a: dict[str, Any],
        role_b: str,
        body_b: dict[str, Any],
    ) -> list[CrossRoleDiffResult]:
        results: list[CrossRoleDiffResult] = []

        keys_a = set(body_a.keys())
        keys_b = set(body_b.keys())

        extra_in_a = keys_a - keys_b
        extra_in_b = keys_b - keys_a

        sensitive_leaked = (extra_in_a | extra_in_b) & _SENSITIVE_FIELDS
        if extra_in_a or extra_in_b:
            confidence = 0.9 if sensitive_leaked else 0.7
            results.append(CrossRoleDiffResult(
                endpoint_path=endpoint_path,
                diff_type=DiffType.STRUCTURAL,
                details={
                    "extra_in_a": sorted(extra_in_a),
                    "extra_in_b": sorted(extra_in_b),
                    "sensitive_leaked": sorted(sensitive_leaked),
                },
                confidence=confidence,
            ))

        common_keys = keys_a & keys_b
        identity_mismatches: dict[str, tuple[Any, Any]] = {}
        value_diffs: dict[str, tuple[Any, Any]] = {}

        for key in common_keys:
            val_a = body_a[key]
            val_b = body_b[key]
            if val_a == val_b:
                continue

            if key.lower() in _IDENTITY_FIELDS:
                identity_mismatches[key] = (val_a, val_b)
            elif _is_masked(val_a) or _is_masked(val_b):
                value_diffs[key] = (val_a, val_b)

        if identity_mismatches:
            results.append(CrossRoleDiffResult(
                endpoint_path=endpoint_path,
                diff_type=DiffType.IDENTITY,
                details={"mismatches": {k: {"a": str(v[0]), "b": str(v[1])} for k, v in identity_mismatches.items()}},
                confidence=0.95,
            ))

        if value_diffs:
            results.append(CrossRoleDiffResult(
                endpoint_path=endpoint_path,
                diff_type=DiffType.VALUE,
                details={"masked_fields": {k: {"a": str(v[0]), "b": str(v[1])} for k, v in value_diffs.items()}},
                confidence=0.6,
            ))

        return results

    def compare_direct(
        self,
        endpoint_path: str,
        role_a: str,
        body_a: dict[str, Any],
        role_b: str,
        body_b: dict[str, Any],
    ) -> list[CrossRoleDiffResult]:
        return self._compare(endpoint_path, role_a, body_a, role_b, body_b)


def _is_masked(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) < 3:
        return False
    star_count = value.count("*")
    return star_count >= len(value) // 2
