# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""HTTPSmugglingPlugin: détecte la vulnérabilité HTTP Request Smuggling (CWE-444)."""
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


class HTTPSmugglingPlugin(HDWPPlugin):
    """Détecte les failles HTTP Request Smuggling (CL.TE et TE.CL)."""

    @property
    def id(self) -> str:
        return "core.configuration.http_smuggling"

    @property
    def name(self) -> str:
        return "HTTP Request Smuggling"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "configuration"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A05:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-444"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not model.endpoints:
            return []
        post_endpoints = [ep for ep in model.endpoints if "POST" in ep.methods][:2]
        if not post_endpoints:
            post_endpoints = model.endpoints[:1]
        hyps: list[Hypothesis] = []
        for ep in post_endpoints:
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"L'endpoint '{ep.path}' est vulnérable au HTTP Request Smuggling (CL.TE)"
                ),
                priority="HIGH",
                priority_rationale=(
                    "HTTP Smuggling = bypass de contrôles de sécurité, "
                    "empoisonnement de cache, vol de sessions"
                ),
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={
                        "endpoint_path": ep.path,
                        "smuggling_type": "cl_te",
                        "payload_type": "http_smuggling",
                    },
                    description=f"HTTP Smuggling CL.TE probe sur {ep.path}",
                )],
            ))
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"L'endpoint '{ep.path}' est vulnérable au HTTP Request Smuggling (TE.CL)"
                ),
                priority="HIGH",
                priority_rationale="HTTP Smuggling = bypass de contrôles de sécurité",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={
                        "endpoint_path": ep.path,
                        "smuggling_type": "te_cl",
                        "payload_type": "http_smuggling",
                    },
                    description=f"HTTP Smuggling TE.CL probe sur {ep.path}",
                )],
            ))
        return hyps
