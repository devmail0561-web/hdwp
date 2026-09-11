# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ReportEngine: agrège les findings et génère les exports (Markdown, JSON, HAR, SARIF).

Abonnement : finding.confirmed → accumule les findings en mémoire.
API publique :
  generate_markdown(output_path) → rapport lisible par sévérité
  generate_json(output_dir)      → findings.json + summary.json
  generate_har(output_dir)       → un .har par finding
  generate_sarif(output_dir)     → findings.sarif (SARIF 2.1.0)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDING_CONFIRMED, HDWPEvent
from hdwp.core.model.schemas import Finding
from hdwp.core.report.har_exporter import build_har
from hdwp.core.report.json_export import compute_summary
from hdwp.core.report.markdown import render_markdown
from hdwp.core.report.sarif_export import build_sarif

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.store.repository import Repository

log = structlog.get_logger()


class ReportEngine:
    """Subscribes to finding.confirmed events and generates reports on demand."""

    def __init__(self, bus: AsyncEventBus, repository: Repository) -> None:
        self._bus = bus
        self._repo = repository
        self._confirmed_findings: list[Finding] = []
        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)

    async def _on_finding_confirmed(self, event: HDWPEvent) -> None:
        data = event.payload
        f = Finding.model_validate(data) if isinstance(data, dict) else data
        self._confirmed_findings.append(f)

    async def _get_findings(self) -> list[Finding]:
        if self._confirmed_findings:
            return self._confirmed_findings
        return await self._repo.list_findings(status="CONFIRMED")

    async def generate_markdown(
        self,
        output_path: Path,
        llm_layer: LLMLayerProtocol | None = None,
        target: str = "cible",
    ) -> None:
        findings = await self._get_findings()

        executive_summary: str | None = None
        if llm_layer is not None and findings:
            try:
                executive_summary = await llm_layer.generate_executive_summary(
                    findings, target
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("report.executive_summary_failed", error=str(exc))

        content = render_markdown(findings, executive_summary=executive_summary)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        log.info("report.markdown_generated", path=str(output_path), findings=len(findings))

    async def generate_json(self, output_dir: Path) -> dict:
        findings = await self._get_findings()
        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "findings.json").write_text(
            json.dumps([f.model_dump() for f in findings], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        summary = compute_summary(findings)
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("report.json_generated", dir=str(output_dir), findings=len(findings))
        return summary

    async def generate_har(self, output_dir: Path) -> None:
        findings = await self._get_findings()
        output_dir.mkdir(parents=True, exist_ok=True)
        for finding in findings:
            har_path = output_dir / f"{finding.id}.har"
            har_path.write_text(
                json.dumps(build_har(finding), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        log.info("report.har_generated", dir=str(output_dir), count=len(findings))

    async def generate_sarif(self, output_dir: Path, tool_version: str = "unknown") -> Path:
        findings = await self._get_findings()
        output_dir.mkdir(parents=True, exist_ok=True)
        sarif_data = build_sarif(findings, tool_version=tool_version)
        sarif_path = output_dir / "findings.sarif"
        sarif_path.write_text(
            json.dumps(sarif_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("report.sarif_generated", path=str(sarif_path), findings=len(findings))
        return sarif_path

    @property
    def findings(self) -> list[Finding]:
        return list(self._confirmed_findings)
