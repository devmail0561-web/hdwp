# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""HAR 1.2 exporter for HDWP findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding


def build_har(finding: Finding) -> dict[str, Any]:
    """Build a minimal HAR 1.2 document for a finding."""
    experiments = finding.proof.get("experiments", [])
    endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else ""

    entries: list[dict[str, Any]] = []
    for exp_id in experiments:
        entries.append({
            "startedDateTime": finding.proof.get("timestamp", ""),
            "_experimentId": exp_id,
            "time": 0,
            "request": {
                "method": "GET",
                "url": endpoint,
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": -1,
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "cookies": [],
                "content": {"size": 0, "mimeType": "application/json"},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
        })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "HDWP Engine", "version": "0.1.0"},
            "entries": entries,
            "comment": f"HDWP Finding {finding.id} — {finding.owasp_category}",
        }
    }
