# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
InfoDisclosurePlugin: détecte l'exposition de données sensibles dans les réponses.

Approche : provoquer des erreurs via field_injection et observer si les messages
d'erreur exposent des informations internes (stack traces, credentials, clés).
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
)
from hdwp.plugins.base import HDWPPlugin


class InfoDisclosurePlugin(HDWPPlugin):
    """Détecte l'exposition non-intentionnelle de données sensibles."""

    @property
    def id(self) -> str:
        return "core.information_flow.info_disclosure"

    @property
    def name(self) -> str:
        return "Information Disclosure"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021", "A02:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-200", "CWE-312"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not model.endpoints:
            return []
        return [SecurityProperty(
            type=PropertyType.CONFIDENTIALITY,
            formal_statement=(
                "Application responses must not expose sensitive data "
                "(credentials, keys, PII) in error messages"
            ),
            model_nodes=[ep.id for ep in model.endpoints[:5]],
            inference_confidence=0.5,
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for ep in model.endpoints[:5]:
            method = ep.methods[0] if ep.methods else "GET"
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"L'endpoint '{ep.path}' expose des données sensibles "
                    f"dans les messages d'erreur"
                ),
                priority="MEDIUM",
                priority_rationale="Information disclosure potentielle via messages d'erreur",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method=method, url=""),
                    mutation_params={
                        "parameter_name": "id",
                        "parameter_location": "path",
                        "payload": "' OR 1=1 --",
                        "payload_type": "sqli",
                    },
                    description=f"Provoquer une erreur sur {ep.path} et observer la réponse",
                )],
            ))
        return hyps[:3]
