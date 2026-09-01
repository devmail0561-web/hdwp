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
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_owasp": by_owasp,
        "avg_confidence": round(avg_conf, 4),
        "generated_at": datetime.now(UTC).isoformat(),
    }
