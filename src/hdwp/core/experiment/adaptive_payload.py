# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    PAYLOAD_ADAPTED,
    WAF_SIGNATURE_DETECTED,
    HDWPEvent,
)
from hdwp.core.experiment.waf_dialog import WAFDialogEngine, WAFType

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

logger = structlog.get_logger()


class SignalType(str, Enum):
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    TIMING_ANOMALY = "TIMING_ANOMALY"
    UNEXPECTED_FIELD = "UNEXPECTED_FIELD"
    NORMAL = "NORMAL"


_BLOCKED_CODES = frozenset({403, 406, 429, 444, 503})
_ERROR_CODES = frozenset({500, 502, 503})
_STACK_TRACE_MARKERS = ("traceback", "stack trace", "at line", "exception in", "error at")


class SignalClassifier:
    def classify(self, status_code: int, body: Any, timing_ms: float, baseline_ms: float) -> SignalType:
        if status_code in _BLOCKED_CODES:
            return SignalType.BLOCKED

        if status_code in _ERROR_CODES and self._has_stack_trace(body):
            return SignalType.ERROR

        if baseline_ms > 0 and timing_ms > baseline_ms * 3:
            return SignalType.TIMING_ANOMALY

        if isinstance(body, dict) and self._has_unexpected_fields(body):
            return SignalType.UNEXPECTED_FIELD

        return SignalType.NORMAL

    def _has_stack_trace(self, body: Any) -> bool:
        if not body:
            return False
        body_str = str(body).lower()
        return any(marker in body_str for marker in _STACK_TRACE_MARKERS)

    def _has_unexpected_fields(self, body: dict[str, Any]) -> bool:
        sensitive = {"password", "token", "secret", "api_key", "internal", "debug"}
        return bool(set(body.keys()) & sensitive)


class AdaptivePayloadEngine:
    def __init__(self, bus: AsyncEventBus) -> None:
        self._bus = bus
        self._waf_engine = WAFDialogEngine()
        self._classifier = SignalClassifier()
        self._detected_wafs: dict[str, WAFType] = {}
        self._baseline_timings: dict[str, float] = {}

        bus.on(EXPERIMENT_RESULT, self._on_experiment_result, mode="stream")

    async def _on_experiment_result(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        response = payload.get("response_received") or {}
        request = payload.get("request_sent") or {}
        status_code = response.get("status_code", 200)
        body = response.get("body")
        timing_ms = payload.get("timing_ms", 0.0)
        endpoint = request.get("url", "")
        hypothesis_id = payload.get("hypothesis_id", "")

        baseline = self._baseline_timings.get(endpoint, 0.0)
        signal = self._classifier.classify(status_code, body, timing_ms, baseline)

        if signal == SignalType.NORMAL:
            if baseline == 0.0:
                self._baseline_timings[endpoint] = timing_ms
            else:
                self._baseline_timings[endpoint] = baseline * 0.9 + timing_ms * 0.1
            return

        if signal == SignalType.BLOCKED:
            headers = response.get("headers", {})
            waf_type = self._waf_engine.identify_waf(headers)
            self._detected_wafs[endpoint] = waf_type
            strategies = self._waf_engine.get_bypass_strategies(waf_type)

            await self._bus.emit(
                WAF_SIGNATURE_DETECTED,
                {
                    "endpoint": endpoint,
                    "waf_type": waf_type.value,
                    "bypass_strategies": [s["name"] for s in strategies],
                    "hypothesis_id": hypothesis_id,
                },
                source="adaptive_payload_engine",
            )

            await self._bus.emit(
                PAYLOAD_ADAPTED,
                {
                    "endpoint": endpoint,
                    "signal_type": signal.value,
                    "adaptation": "waf_bypass",
                    "waf_type": waf_type.value,
                    "strategies": strategies,
                    "hypothesis_id": hypothesis_id,
                },
                source="adaptive_payload_engine",
            )

        elif signal == SignalType.ERROR:
            db_hints = self._extract_db_hints(body)
            await self._bus.emit(
                PAYLOAD_ADAPTED,
                {
                    "endpoint": endpoint,
                    "signal_type": signal.value,
                    "adaptation": "error_refinement",
                    "db_hints": db_hints,
                    "hypothesis_id": hypothesis_id,
                },
                source="adaptive_payload_engine",
            )

        elif signal == SignalType.TIMING_ANOMALY:
            await self._bus.emit(
                PAYLOAD_ADAPTED,
                {
                    "endpoint": endpoint,
                    "signal_type": signal.value,
                    "adaptation": "timing_escalation",
                    "timing_ms": timing_ms,
                    "baseline_ms": baseline,
                    "hypothesis_id": hypothesis_id,
                },
                source="adaptive_payload_engine",
            )

        elif signal == SignalType.UNEXPECTED_FIELD:
            await self._bus.emit(
                PAYLOAD_ADAPTED,
                {
                    "endpoint": endpoint,
                    "signal_type": signal.value,
                    "adaptation": "field_investigation",
                    "hypothesis_id": hypothesis_id,
                },
                source="adaptive_payload_engine",
            )

    def _extract_db_hints(self, body: Any) -> dict[str, str]:
        if not body:
            return {}
        body_str = str(body).lower()
        hints: dict[str, str] = {}
        db_markers = {
            "postgresql": "PostgreSQL",
            "mysql": "MySQL",
            "oracle": "Oracle",
            "sqlite": "SQLite",
            "mssql": "MSSQL",
            "sql server": "MSSQL",
        }
        for marker, db_name in db_markers.items():
            if marker in body_str:
                hints["database"] = db_name
                break
        return hints

    @property
    def detected_wafs(self) -> dict[str, WAFType]:
        return dict(self._detected_wafs)
