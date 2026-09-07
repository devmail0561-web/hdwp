# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    TEMPORAL_ANOMALY_DETECTED,
    HDWPEvent,
)

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus

logger = structlog.get_logger()

MIN_SAMPLES = 5
ANOMALY_SIGMA = 2.0
ESCALATION_DELAYS = [1.0, 3.0, 7.0]


@dataclass
class TimingBaseline:
    samples: list[float] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def mean(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)

    @property
    def stddev(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        m = self.mean
        variance = sum((s - m) ** 2 for s in self.samples) / (len(self.samples) - 1)
        return math.sqrt(variance)

    @property
    def p95(self) -> float:
        if not self.samples:
            return 0.0
        sorted_s = sorted(self.samples)
        idx = math.ceil(0.95 * len(sorted_s)) - 1
        return sorted_s[max(0, idx)]

    def add(self, timing_ms: float) -> None:
        self.samples.append(timing_ms)

    @property
    def threshold(self) -> float:
        return self.p95 + ANOMALY_SIGMA * self.stddev


@dataclass
class TemporalAnomaly:
    endpoint_path: str
    timing_ms: float
    baseline_p95: float
    baseline_stddev: float
    threshold: float
    escalation_level: int = 0
    hypothesis_id: str = ""


class TemporalAnomalyDetector:
    def __init__(self, bus: AsyncEventBus) -> None:
        self._bus = bus
        self._baselines: dict[str, TimingBaseline] = defaultdict(TimingBaseline)
        self._anomaly_counts: dict[str, int] = defaultdict(int)

        bus.on(EXPERIMENT_RESULT, self._on_experiment_result)

    async def _on_experiment_result(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        timing_ms = payload.get("timing_ms", 0.0)
        if not timing_ms or timing_ms <= 0:
            return

        request = payload.get("request_sent") or {}
        endpoint = request.get("url", "")
        if not endpoint:
            return

        hypothesis_id = payload.get("hypothesis_id", "")
        baseline = self._baselines[endpoint]

        if baseline.count < MIN_SAMPLES:
            baseline.add(timing_ms)
            return

        threshold = baseline.threshold
        if timing_ms > threshold:
            self._anomaly_counts[endpoint] += 1
            escalation = min(
                self._anomaly_counts[endpoint] - 1,
                len(ESCALATION_DELAYS) - 1,
            )

            anomaly = TemporalAnomaly(
                endpoint_path=endpoint,
                timing_ms=timing_ms,
                baseline_p95=baseline.p95,
                baseline_stddev=baseline.stddev,
                threshold=threshold,
                escalation_level=escalation,
                hypothesis_id=hypothesis_id,
            )

            await self._bus.emit(
                TEMPORAL_ANOMALY_DETECTED,
                {
                    "endpoint_path": anomaly.endpoint_path,
                    "timing_ms": anomaly.timing_ms,
                    "baseline_p95": round(anomaly.baseline_p95, 2),
                    "threshold": round(anomaly.threshold, 2),
                    "escalation_level": anomaly.escalation_level,
                    "suggested_delay": ESCALATION_DELAYS[escalation],
                    "hypothesis_id": anomaly.hypothesis_id,
                },
                source="temporal_anomaly_detector",
            )
            logger.info(
                "temporal.anomaly_detected",
                endpoint=endpoint,
                timing_ms=round(timing_ms, 1),
                threshold=round(threshold, 1),
                escalation=escalation,
            )
        else:
            baseline.add(timing_ms)

    def get_baseline(self, endpoint: str) -> TimingBaseline | None:
        bl = self._baselines.get(endpoint)
        if bl and bl.count > 0:
            return bl
        return None

    def get_anomaly_count(self, endpoint: str) -> int:
        return self._anomaly_counts.get(endpoint, 0)
