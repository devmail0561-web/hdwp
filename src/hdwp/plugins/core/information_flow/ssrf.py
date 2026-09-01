# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SSRFPlugin: détecte les vulnérabilités SSRF (Server-Side Request Forgery).

Approche sans callback server : injecter des URLs pointant vers des adresses
privées/localhost et observer les indicateurs heuristiques dans la réponse
(erreurs de connexion, contenu de fichiers internes, délais anormaux).
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

_URL_KEYWORDS = frozenset({"url", "callback", "redirect", "webhook", "endpoint", "src", "dest"})

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254",           # AWS metadata
    "http://metadata.google.internal",  # GCP metadata
]


class SSRFPlugin(HDWPPlugin):
    """Détecte les vulnérabilités SSRF via des payloads d'URLs internes."""

    @property
    def id(self) -> str:
        return "core.information_flow.ssrf"

    @property
    def name(self) -> str:
        return "SSRF Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A10:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-918"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        url_params = self._url_params(model)
        if not url_params:
            return []
        return [SecurityProperty(
            type=PropertyType.INTEGRITY,
            formal_statement=(
                f"URL parameter '{url_params[0].name}' must not allow "
                f"server-side requests to internal resources"
            ),
            model_nodes=[url_params[0].id],
            inference_confidence=0.7,
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for param in self._url_params(model)[:2]:
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"Le paramètre '{param.name}' permet des requêtes SSRF "
                    f"vers des ressources internes"
                ),
                priority="HIGH",
                priority_rationale="SSRF peut exposer les services internes et les métadonnées cloud",
                required_experiments=[
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "ssrf",
                        },
                        description=f"SSRF probe: {param.name}={payload}",
                    )
                    for payload in SSRF_PAYLOADS
                ],
            ))
        return hyps

    @staticmethod
    def _url_params(model: ApplicationModelData) -> list:
        return [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in _URL_KEYWORDS)
        ]
