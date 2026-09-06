# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
OpenRedirectPlugin: détecte les vulnérabilités de redirection ouverte.
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
    generate_id,
)
from hdwp.plugins.base import HDWPPlugin

REDIRECT_PARAM_KEYWORDS = frozenset({
    "redirect", "next", "return", "continue", "goto",
    "forward", "target", "dest", "destination", "callback",
})

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.hdwp-test.invalid",
    "//evil.hdwp-test.invalid",
    "https://evil.hdwp-test.invalid%2F",
]


class OpenRedirectPlugin(HDWPPlugin):
    """Détecte les vulnérabilités de redirection ouverte (open redirect)."""

    @property
    def id(self) -> str:
        return "core.information_flow.open_redirect"

    @property
    def name(self) -> str:
        return "Open Redirect Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-601"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in REDIRECT_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]
        if not candidates:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement="redirect parameters must validate destination against an allowlist",
                model_nodes=[p.id for p in candidates[:5]],
                inference_confidence=0.75,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in REDIRECT_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:5]

        hypotheses = []
        for param in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "payload": payload,
                        "payload_type": "open_redirect",
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                    },
                    description=f"Open redirect: {param.name}={payload[:40]}",
                )
                for payload in OPEN_REDIRECT_PAYLOADS
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' permet une redirection vers un domaine externe",
                    priority="MEDIUM",
                    priority_rationale="Open redirect facilite le phishing et l'abus OAuth2",
                    required_experiments=experiments,
                )
            )
        return hypotheses
