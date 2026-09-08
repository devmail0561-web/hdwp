# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""JSON export helpers for HDWP findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding


def compute_summary(findings: list[Finding]) -> dict[str, Any]:
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_owasp: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_owasp[f.owasp_category] = by_owasp.get(f.owasp_category, 0) + 1

    avg_conf = sum(f.confidence for f in findings) / len(findings) if findings else 0.0
    explained = [f for f in findings if f.explanation is not None]
    top_signals: dict[str, int] = {}
    for f in explained:
        for c in (f.explanation.top_contributors if f.explanation else []):
            if abs(c.contribution) > 0.01:
                top_signals[c.dimension] = top_signals.get(c.dimension, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_owasp": by_owasp,
        "avg_confidence": round(avg_conf, 4),
        "explained_count": len(explained),
        "top_contributing_signals": dict(sorted(top_signals.items(), key=lambda x: -x[1])),
        "generated_at": datetime.now(UTC).isoformat(),
    }
