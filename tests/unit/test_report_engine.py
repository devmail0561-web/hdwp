# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDING_CONFIRMED
from hdwp.core.model.schemas import ConfidenceScore, Finding, generate_id
from hdwp.core.report.engine import ReportEngine
from hdwp.core.report.json_export import compute_summary
from hdwp.core.report.markdown import render_markdown


def _make_finding(severity: str = "HIGH", owasp: str = "A01:2021", cwe: str = "CWE-639") -> Finding:
    return Finding(
        id=generate_id("FIND"),
        hypothesis_id=generate_id("HYP"),
        property_id=generate_id("PROP"),
        status="CONFIRMED",
        confidence=0.92,
        confidence_breakdown=ConfidenceScore(overall=0.92),
        owasp_category=owasp,
        cwe_id=cwe,
        severity=severity,
        affected_endpoints=["/api/users/1"],
        proof={
            "experiments": ["EXP-001", "EXP-002"],
            "diffs": ["DIFF-001"],
            "reproduction_steps": ["1. GET /api/users/1", "2. Response contient les données"],
        },
        remediation_hint="Vérifier l'ownership côté serveur.",
    )


class MockRepository:
    def __init__(self, findings: list[Finding] | None = None):
        self._findings = findings or []

    async def list_findings(self, status: str | None = None) -> list[Finding]:
        if status:
            return [f for f in self._findings if f.status == status]
        return self._findings

    async def list_hypotheses(self, status: str | None = None):
        return []


@pytest.mark.asyncio
async def test_report_engine_subscribes_to_finding_confirmed() -> None:
    bus = AsyncEventBus()
    repo = MockRepository()
    engine = ReportEngine(bus, repo)

    f = _make_finding()
    await bus.emit(FINDING_CONFIRMED, f.model_dump(), source="test")
    await bus.drain()

    assert len(engine.findings) == 1
    assert engine.findings[0].id == f.id


@pytest.mark.asyncio
async def test_markdown_generated(tmp_path: Path) -> None:
    bus = AsyncEventBus()
    findings = [_make_finding("HIGH"), _make_finding("MEDIUM"), _make_finding("INFO")]
    repo = MockRepository(findings)
    engine = ReportEngine(bus, repo)

    out = tmp_path / "report.md"
    await engine.generate_markdown(out)

    assert out.exists()
    content = out.read_text()
    assert "Rapport HDWP" in content
    for f in findings:
        assert f.id in content


@pytest.mark.asyncio
async def test_markdown_empty_findings(tmp_path: Path) -> None:
    bus = AsyncEventBus()
    repo = MockRepository([])
    engine = ReportEngine(bus, repo)

    out = tmp_path / "report.md"
    await engine.generate_markdown(out)

    content = out.read_text()
    assert "Aucun finding confirmé" in content


@pytest.mark.asyncio
async def test_markdown_sections_by_severity(tmp_path: Path) -> None:
    bus = AsyncEventBus()
    repo = MockRepository([_make_finding("HIGH"), _make_finding("HIGH")])
    engine = ReportEngine(bus, repo)

    out = tmp_path / "report.md"
    await engine.generate_markdown(out)
    content = out.read_text()

    assert "Hauts" in content
    assert "Moyens" not in content  # no MEDIUM findings


@pytest.mark.asyncio
async def test_json_generated(tmp_path: Path) -> None:
    bus = AsyncEventBus()
    findings = [_make_finding("HIGH"), _make_finding("LOW")]
    repo = MockRepository(findings)
    engine = ReportEngine(bus, repo)

    summary = await engine.generate_json(tmp_path)

    findings_file = tmp_path / "findings.json"
    summary_file = tmp_path / "summary.json"
    assert findings_file.exists()
    assert summary_file.exists()

    data = json.loads(findings_file.read_text())
    assert len(data) == 2

    assert summary["total"] == 2
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["LOW"] == 1


def test_summary_counts() -> None:
    findings = [
        _make_finding("HIGH"),
        _make_finding("HIGH"),
        _make_finding("MEDIUM"),
        _make_finding("INFO"),
    ]
    summary = compute_summary(findings)

    assert summary["total"] == 4
    assert summary["by_severity"]["HIGH"] == 2
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_severity"]["INFO"] == 1
    assert summary["by_severity"]["CRITICAL"] == 0
    assert "avg_confidence" in summary
    assert "generated_at" in summary


@pytest.mark.asyncio
async def test_har_generated(tmp_path: Path) -> None:
    bus = AsyncEventBus()
    findings = [_make_finding("HIGH"), _make_finding("MEDIUM")]
    repo = MockRepository(findings)
    engine = ReportEngine(bus, repo)

    har_dir = tmp_path / "har"
    await engine.generate_har(har_dir)

    har_files = list(har_dir.glob("*.har"))
    assert len(har_files) == 2
    for hf in har_files:
        har = json.loads(hf.read_text())
        assert "log" in har
        assert har["log"]["version"] == "1.2"
