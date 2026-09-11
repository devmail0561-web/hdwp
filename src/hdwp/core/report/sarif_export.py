# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SARIF 2.1.0 export for HDWP findings.

Produces a SARIF log compatible with GitHub Code Scanning, DefectDojo,
and VS Code Security extensions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def build_sarif(findings: list[Finding], tool_version: str = "unknown") -> dict:
    confirmed = [f for f in findings if f.status == "CONFIRMED"]
    rule_ids = sorted({_rule_id(f) for f in confirmed})
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hdwp",
                        "version": tool_version,
                        "informationUri": "https://github.com/devmail0561-web/hdwp",
                        "rules": [_build_rule(r) for r in rule_ids],
                    }
                },
                "results": [_build_result(f) for f in confirmed],
            }
        ],
    }


def _rule_id(f: Finding) -> str:
    return f.owasp_category or f.cwe_id or "UNKNOWN"


def _build_rule(rule_id: str) -> dict:
    return {
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "helpUri": "https://owasp.org/www-project-top-ten/",
        "properties": {"tags": ["security"]},
    }


def _build_result(f: Finding) -> dict:
    level = _SEVERITY_TO_LEVEL.get(f.severity, "warning")
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": ep, "uriBaseId": "%SRCROOT%"}
            }
        }
        for ep in f.affected_endpoints[:3]
    ]
    if not locations:
        locations = [{"physicalLocation": {"artifactLocation": {"uri": "unknown"}}}]

    result: dict = {
        "ruleId": _rule_id(f),
        "level": level,
        "message": {
            "text": f.remediation_hint or f"{f.owasp_category or f.cwe_id or 'vulnerability'} detected"
        },
        "locations": locations,
        "partialFingerprints": {"hdwp/confidence/v1": str(round(f.confidence, 4))},
        "properties": {
            "owasp": f.owasp_category,
            "cwe": f.cwe_id,
            "confidence": f.confidence,
            "finding_id": f.id,
            "severity": f.severity,
        },
    }
    if f.cwe_id:
        cwe_num = f.cwe_id.replace("CWE-", "")
        if cwe_num.isdigit():
            result["taxa"] = [{"toolComponent": {"name": "CWE"}, "id": f.cwe_id}]
    return result
