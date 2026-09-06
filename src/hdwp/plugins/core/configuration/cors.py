# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CORSPlugin: teste les politiques CORS permissives.

Mutation active : envoie Origin: https://evil.hdwp-test.invalid et vérifie
si Access-Control-Allow-Origin reflète cette origine ou retourne '*'.
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

EVIL_ORIGIN = "https://evil.hdwp-test.invalid"


class CORSPlugin(HDWPPlugin):
    """Détecte les mauvaises configurations CORS."""

    @property
    def id(self) -> str:
        return "core.configuration.cors"

    @property
    def name(self) -> str:
        return "CORS Misconfiguration"

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
        return ["CWE-942"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not model.endpoints:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.COHERENCE,
                formal_statement=(
                    "CORS: seules les origines explicitement autorisées "
                    "peuvent lire les réponses cross-origin"
                ),
                model_nodes=[ep.id for ep in model.endpoints[:3]],
                inference_confidence=0.6,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        # Prioriser les endpoints authentifiés — éviter le bruit sur endpoints publics
        auth_endpoints = [ep for ep in model.endpoints if ep.auth_required or ep.roles_observed]
        # Si aucun endpoint authentifié, tester tous (cas d'une API publique)
        candidates = (auth_endpoints or model.endpoints)[:5]
        for ep in candidates:
            hyps.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"L'endpoint '{ep.path}' accepte des requêtes cross-origin "
                        f"depuis n'importe quelle origine"
                    ),
                    priority="MEDIUM",
                    priority_rationale="CORS permissif expose les données aux sites malveillants",
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="origin_test",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "evil_origin": EVIL_ORIGIN,
                                "endpoint_path": ep.path,
                            },
                            description=f"CORS test: Origin: {EVIL_ORIGIN} sur {ep.path}",
                        )
                    ],
                )
            )
        return hyps
