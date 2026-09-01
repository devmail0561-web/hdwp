# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Markdown report renderer for HDWP findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import Finding

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_LABELS = {
    "CRITICAL": "Critiques",
    "HIGH": "Hauts",
    "MEDIUM": "Moyens",
    "LOW": "Bas",
    "INFO": "Informationnels",
}


def render_markdown(
    findings: list[Finding],
    executive_summary: str | None = None,
) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines.append(f"# Rapport HDWP — {now}\n")

    # Executive summary
    lines.append("## Résumé exécutif\n")
    if not findings:
        lines.append("Aucun finding confirmé.\n")
    elif executive_summary:
        lines.append(f"{executive_summary}\n")
    else:
        by_sev: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        counts = ", ".join(f"{s}: {n}" for s, n in by_sev.items() if n > 0)
        lines.append(f"{len(findings)} finding(s) confirmé(s) : {counts}\n")

    # Findings by severity
    by_sev_map: dict[str, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev_map.setdefault(f.severity, []).append(f)

    for sev in _SEVERITY_ORDER:
        sev_findings = by_sev_map.get(sev, [])
        if not sev_findings:
            continue
        label = _SEVERITY_LABELS.get(sev, sev)
        lines.append(f"## Findings {label}\n")
        for f in sev_findings:
            ep = f.affected_endpoints[0] if f.affected_endpoints else "—"
            steps = f.proof.get("reproduction_steps", [])
            exps = f.proof.get("experiments", [])
            diffs = f.proof.get("diffs", [])

            lines.append(f"### {f.id} — {f.owasp_category} | {f.cwe_id} | {sev}\n")
            lines.append(f"**Endpoint :** `{ep}`  ")
            lines.append(f"**Confiance :** {f.confidence:.0%}  ")
            lines.append(f"**OWASP :** {f.owasp_category}  ")
            lines.append(f"**CWE :** {f.cwe_id}\n")

            if steps:
                lines.append(f"**Résumé :** {steps[0]}\n")
                lines.append("**Étapes de reproduction :**\n")
                for i, step in enumerate(steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            lines.append(f"**Remédiation :** {f.remediation_hint}\n")
            lines.append("**Preuve :**")
            lines.append(f"- Expériences : {', '.join(exps) if exps else '—'}")
            lines.append(f"- Diffs : {', '.join(diffs) if diffs else '—'}\n")
            lines.append("---\n")

    # Methodology
    lines.append("## Méthodologie\n")
    lines.append(
        f"HDWP Engine v{__import__('hdwp').__version__} — Moteur de test de sécurité property-driven.  \n"
        "Boucle : OBSERVE → MODEL → INFER PROPERTIES → HYPOTHESIZE → EXPERIMENT → ORACLE → FINDING\n"
    )

    return "\n".join(lines)
