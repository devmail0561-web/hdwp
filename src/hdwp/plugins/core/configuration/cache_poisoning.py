# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""CachePoisoningPlugin: détecte le Web Cache Poisoning (CWE-345)."""
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

CACHE_POISON_PAYLOADS = [
    ("X-Forwarded-Host", "evil.hdwp-test.invalid"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
]


class CachePoisoningPlugin(HDWPPlugin):
    """Détecte la possibilité d'empoisonner le cache web via headers non normalisés."""

    @property
    def id(self) -> str:
        return "core.configuration.cache_poisoning"

    @property
    def name(self) -> str:
        return "Web Cache Poisoning"

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
        return ["CWE-345"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not model.endpoints:
            return []
        get_endpoints = [
            ep for ep in model.endpoints
            if "GET" in ep.methods
            and not any(x in ep.path for x in ("/api/", "/graphql"))
        ][:3]
        if not get_endpoints:
            get_endpoints = model.endpoints[:2]
        hyps: list[Hypothesis] = []
        for ep in get_endpoints:
            for header_name, header_value in CACHE_POISON_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"L'endpoint '{ep.path}' reflète le header '{header_name}' "
                        f"— cache poisoning possible"
                    ),
                    priority="MEDIUM",
                    priority_rationale=(
                        "Cache poisoning = diffusion de contenu malveillant "
                        "à tous les utilisateurs"
                    ),
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": header_name,
                            "parameter_location": "header",
                            "payload": header_value,
                            "payload_type": "cache_poison",
                        },
                        description=(
                            f"Cache poison test: {header_name}: {header_value} sur {ep.path}"
                        ),
                    )],
                ))
        return hyps
