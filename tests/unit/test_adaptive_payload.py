# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    HDWPEvent,
    PAYLOAD_ADAPTED,
    WAF_SIGNATURE_DETECTED,
)
from hdwp.core.experiment.adaptive_payload import (
    AdaptivePayloadEngine,
    SignalClassifier,
    SignalType,
)
from hdwp.core.experiment.waf_dialog import WAFDialogEngine, WAFType


class StubBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Any]] = {}
        self._stream_handlers: dict[str, list[Any]] = {}
        self.emitted: list[HDWPEvent] = []

    def on(self, event_type: str, handler: Any, *, mode: str = "batch") -> None:
        if mode == "stream":
            self._stream_handlers.setdefault(event_type, []).append(handler)
        else:
            self._handlers.setdefault(event_type, []).append(handler)

    async def emit(
        self, event_or_type: Any, payload: Any = None, source: str = ""
    ) -> None:
        if isinstance(event_or_type, HDWPEvent):
            event = event_or_type
        else:
            event = HDWPEvent(type=event_or_type, source=source, payload=payload)
        self.emitted.append(event)
        for handler in self._stream_handlers.get(event.type, []):
            result = handler(event)
            if asyncio.iscoroutine(result):
                await result
        for handler in self._handlers.get(event.type, []):
            result = handler(event)
            if asyncio.iscoroutine(result):
                await result


def _make_experiment_result(
    status_code: int = 200,
    body: Any = None,
    headers: dict[str, str] | None = None,
    url: str = "/api/users",
    timing_ms: float = 100.0,
    hypothesis_id: str = "HYP-001",
) -> dict[str, Any]:
    return {
        "response_received": {
            "status_code": status_code,
            "body": body,
            "headers": headers or {},
        },
        "request_sent": {"url": url},
        "timing_ms": timing_ms,
        "hypothesis_id": hypothesis_id,
    }


# ── SignalClassifier ──────────────────────────────────────────────────────────


class TestSignalClassifier:
    def test_blocked_for_403(self):
        c = SignalClassifier()
        assert c.classify(403, "", 100.0, 100.0) is SignalType.BLOCKED

    def test_blocked_for_406_429(self):
        c = SignalClassifier()
        for code in (406, 429):
            assert c.classify(code, "", 100.0, 100.0) is SignalType.BLOCKED

    def test_503_classified_as_error_not_blocked(self):
        # 503 = erreur serveur (stack trace potentielle) — pas un blocage WAF
        c = SignalClassifier()
        body = "Service Unavailable\nTraceback (most recent call last):\n  File app.py"
        assert c.classify(503, body, 100.0, 100.0) is SignalType.ERROR

    def test_error_for_500_with_stack_trace(self):
        c = SignalClassifier()
        body = "Internal Server Error\nTraceback (most recent call last):\n  File..."
        assert c.classify(500, body, 100.0, 100.0) is SignalType.ERROR

    def test_timing_anomaly_when_exceeds_3x_baseline(self):
        c = SignalClassifier()
        assert c.classify(200, {}, 350.0, 100.0) is SignalType.TIMING_ANOMALY

    def test_unexpected_field_for_sensitive_keys(self):
        c = SignalClassifier()
        body = {"name": "alice", "token": "abc123", "id": 1}
        assert c.classify(200, body, 100.0, 100.0) is SignalType.UNEXPECTED_FIELD

    def test_normal_for_clean_response(self):
        c = SignalClassifier()
        body = {"name": "alice", "id": 1}
        assert c.classify(200, body, 100.0, 100.0) is SignalType.NORMAL


# ── WAFDialogEngine ──────────────────────────────────────────────────────────


class TestWAFDialogEngine:
    def test_identify_cloudflare_from_cf_ray(self):
        waf = WAFDialogEngine()
        assert waf.identify_waf({"cf-ray": "abc123"}) is WAFType.CLOUDFLARE

    def test_identify_aws_waf_from_amzn_header(self):
        waf = WAFDialogEngine()
        assert waf.identify_waf({"x-amzn-requestid": "abc"}) is WAFType.AWS_WAF

    def test_unknown_for_unrecognized_headers(self):
        waf = WAFDialogEngine()
        assert waf.identify_waf({"x-custom": "value"}) is WAFType.UNKNOWN


# ── AdaptivePayloadEngine ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_response_emits_waf_and_payload_adapted():
    bus = StubBus()
    AdaptivePayloadEngine(bus)

    payload = _make_experiment_result(
        status_code=403,
        body="Forbidden",
        headers={"cf-ray": "abc123"},
    )
    await bus.emit(EXPERIMENT_RESULT, payload, source="test")

    waf_events = [e for e in bus.emitted if e.type == WAF_SIGNATURE_DETECTED]
    adapted_events = [e for e in bus.emitted if e.type == PAYLOAD_ADAPTED]

    assert len(waf_events) == 1
    assert waf_events[0].payload["waf_type"] == "cloudflare"
    assert waf_events[0].payload["endpoint"] == "/api/users"

    assert len(adapted_events) == 1
    assert adapted_events[0].payload["adaptation"] == "waf_bypass"
    assert adapted_events[0].payload["signal_type"] == "BLOCKED"


@pytest.mark.asyncio
async def test_error_response_emits_error_refinement():
    bus = StubBus()
    AdaptivePayloadEngine(bus)

    payload = _make_experiment_result(
        status_code=500,
        body="Error: Traceback (most recent call last): PostgreSQL syntax error",
    )
    await bus.emit(EXPERIMENT_RESULT, payload, source="test")

    adapted_events = [e for e in bus.emitted if e.type == PAYLOAD_ADAPTED]
    assert len(adapted_events) == 1
    assert adapted_events[0].payload["adaptation"] == "error_refinement"
    assert adapted_events[0].payload["db_hints"]["database"] == "PostgreSQL"


@pytest.mark.asyncio
async def test_timing_anomaly_emits_timing_escalation():
    bus = StubBus()
    engine = AdaptivePayloadEngine(bus)
    engine._baseline_timings["/api/users"] = 100.0

    payload = _make_experiment_result(timing_ms=350.0)
    await bus.emit(EXPERIMENT_RESULT, payload, source="test")

    adapted_events = [e for e in bus.emitted if e.type == PAYLOAD_ADAPTED]
    assert len(adapted_events) == 1
    assert adapted_events[0].payload["adaptation"] == "timing_escalation"
    assert adapted_events[0].payload["timing_ms"] == 350.0
    assert adapted_events[0].payload["baseline_ms"] == 100.0


@pytest.mark.asyncio
async def test_normal_response_updates_baseline_no_event():
    bus = StubBus()
    engine = AdaptivePayloadEngine(bus)

    payload = _make_experiment_result(
        status_code=200, body={"id": 1}, timing_ms=120.0
    )
    await bus.emit(EXPERIMENT_RESULT, payload, source="test")

    adapted_events = [e for e in bus.emitted if e.type == PAYLOAD_ADAPTED]
    waf_events = [e for e in bus.emitted if e.type == WAF_SIGNATURE_DETECTED]
    assert len(adapted_events) == 0
    assert len(waf_events) == 0
    assert engine._baseline_timings["/api/users"] == 120.0
