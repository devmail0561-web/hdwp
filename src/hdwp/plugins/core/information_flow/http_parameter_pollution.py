# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""HTTPParameterPollutionPlugin: détecte le HTTP Parameter Pollution (CWE-235)."""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    SecurityProperty,
)
from hdwp.plugins.base import HDWPPlugin


class HTTPParameterPollutionPlugin(HDWPPlugin):
    """Détecte les failles HTTP Parameter Pollution (HPP)."""

    @property
    def id(self) -> str:
        return "core.information_flow.http_parameter_pollution"

    @property
    def name(self) -> str:
        return "HTTP Parameter Pollution (HPP)"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A03:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-235"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        query_params = [
            p for p in model.parameters
            if p.location == "query" and p.type_inferred in ("string", "integer")
        ][:5]
        if not query_params:
            return []
        hyps: list[Hypothesis] = []
        for param in query_params:
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"Le paramètre '{param.name}' est vulnérable à HPP "
                    f"— duplication avec valeurs conflictuelles"
                ),
                priority="LOW",
                priority_rationale=(
                    "HPP peut bypasser validations et modifier comportement applicatif"
                ),
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "parameter_name": param.name,
                        "parameter_location": "query",
                        "payload": f"original_value&{param.name}=injected",
                        "payload_type": "hpp",
                    },
                    description=f"HPP test: dupliquer {param.name} avec valeurs conflictuelles",
                )],
            ))
        return hyps[:5]
