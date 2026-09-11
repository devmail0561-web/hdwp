# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.model.schemas import ConfidenceScore, Finding, generate_id
from hdwp.core.report.sarif_export import SARIF_SCHEMA, SARIF_VERSION, build_sarif


_SENTINEL: list[str] = []


def _finding(
    status: str = "CONFIRMED",
    severity: str = "HIGH",
    owasp: str = "A01:2021",
    cwe: str = "CWE-639",
    endpoints: list[str] | None = None,
    hint: str = "Check ownership server-side.",
) -> Finding:
    if endpoints is None:
        eps = ["/api/users/1"]
    else:
        eps = endpoints
    return Finding(
        id=generate_id("FIND"),
        hypothesis_id=generate_id("HYP"),
        property_id=generate_id("PROP"),
        status=status,
        confidence=0.92,
        confidence_breakdown=ConfidenceScore(overall=0.92),
        owasp_category=owasp,
        cwe_id=cwe,
        severity=severity,
        affected_endpoints=eps,
        remediation_hint=hint,
    )


# ── structure ─────────────────────────────────────────────────────────────────


def test_sarif_schema_and_version_present() -> None:
    sarif = build_sarif([])
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == SARIF_VERSION


def test_sarif_has_runs_with_driver() -> None:
    sarif = build_sarif([])
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "hdwp"


def test_sarif_empty_findings_gives_no_results() -> None:
    sarif = build_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# ── filtering ────────────────────────────────────────────────────────────────


def test_only_confirmed_findings_in_results() -> None:
    confirmed = _finding(status="CONFIRMED")
    refuted = _finding(status="REFUTED")
    sarif = build_sarif([confirmed, refuted])
    assert len(sarif["runs"][0]["results"]) == 1


def test_refuted_only_gives_empty_results() -> None:
    sarif = build_sarif([_finding(status="REFUTED")])
    assert sarif["runs"][0]["results"] == []


# ── result content ───────────────────────────────────────────────────────────


def test_result_rule_id_uses_owasp_category() -> None:
    sarif = build_sarif([_finding(owasp="A01:2021")])
    assert sarif["runs"][0]["results"][0]["ruleId"] == "A01:2021"


def test_result_rule_id_falls_back_to_cwe_when_no_owasp() -> None:
    sarif = build_sarif([_finding(owasp="", cwe="CWE-200")])
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-200"


@pytest.mark.parametrize("severity, expected_level", [
    ("CRITICAL", "error"),
    ("HIGH", "error"),
    ("MEDIUM", "warning"),
    ("LOW", "note"),
    ("INFO", "note"),
])
def test_severity_maps_to_sarif_level(severity: str, expected_level: str) -> None:
    sarif = build_sarif([_finding(severity=severity)])
    assert sarif["runs"][0]["results"][0]["level"] == expected_level


def test_result_has_confidence_fingerprint() -> None:
    sarif = build_sarif([_finding()])
    fp = sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert "hdwp/confidence/v1" in fp


def test_result_properties_contain_owasp_and_cwe() -> None:
    sarif = build_sarif([_finding(owasp="A01:2021", cwe="CWE-639")])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["owasp"] == "A01:2021"
    assert props["cwe"] == "CWE-639"


# ── CWE taxa ─────────────────────────────────────────────────────────────────


def test_cwe_id_adds_taxa_entry() -> None:
    sarif = build_sarif([_finding(cwe="CWE-639")])
    result = sarif["runs"][0]["results"][0]
    assert "taxa" in result
    assert result["taxa"][0]["id"] == "CWE-639"


def test_no_taxa_when_cwe_empty() -> None:
    sarif = build_sarif([_finding(cwe="")])
    result = sarif["runs"][0]["results"][0]
    assert "taxa" not in result


# ── rules dedup ──────────────────────────────────────────────────────────────


def test_rules_deduplicated_across_findings() -> None:
    findings = [_finding(owasp="A01:2021"), _finding(owasp="A01:2021"), _finding(owasp="A03:2021")]
    sarif = build_sarif(findings)
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert "A01:2021" in rule_ids
    assert "A03:2021" in rule_ids


# ── locations ────────────────────────────────────────────────────────────────


def test_affected_endpoints_map_to_locations() -> None:
    sarif = build_sarif([_finding(endpoints=["/api/users/1", "/api/admin"])])
    locations = sarif["runs"][0]["results"][0]["locations"]
    uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations]
    assert "/api/users/1" in uris
    assert "/api/admin" in uris


def test_no_endpoints_gives_unknown_location() -> None:
    sarif = build_sarif([_finding(endpoints=[])])
    locations = sarif["runs"][0]["results"][0]["locations"]
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "unknown"


def test_at_most_three_locations_per_result() -> None:
    eps = [f"/ep/{i}" for i in range(10)]
    sarif = build_sarif([_finding(endpoints=eps)])
    assert len(sarif["runs"][0]["results"][0]["locations"]) <= 3


# ── tool_version ─────────────────────────────────────────────────────────────


def test_tool_version_propagated() -> None:
    sarif = build_sarif([], tool_version="1.2.3")
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "1.2.3"
