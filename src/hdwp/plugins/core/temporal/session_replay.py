# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SessionReplayPlugin: détecte les tokens de session non invalidés après logout.

Utilise la mutation token_reuse (mutation enregistrée).
Détection via TemporalModule.run_token_reuse() existant.
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

# Mots-clés pour identifier les endpoints de logout
LOGOUT_KEYWORDS = frozenset({
    "logout", "signout", "disconnect", "destroy", "invalidate",
    "deauth", "close", "exit",
})


class SessionReplayPlugin(HDWPPlugin):
    """Détecte les tokens de session non invalidés après logout."""

    @property
    def id(self) -> str:
        return "core.temporal.session_replay"

    @property
    def name(self) -> str:
        return "Session Replay Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "temporal"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A07:2021"]  # Identification and Authentication Failures

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-613"]  # Insufficient Session Expiration

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Infère des propriétés TEMPORAL pour les sessions authentifiées."""
        properties: list[SecurityProperty] = []

        # Chercher endpoints authentifiés
        auth_endpoints = [
            ep for ep in model.endpoints
            if ep.auth_required or ep.roles_observed
        ]

        # Chercher endpoints de logout
        logout_endpoints = [
            ep for ep in model.endpoints
            if any(kw in ep.path.lower() for kw in LOGOUT_KEYWORDS)
        ]

        if auth_endpoints and logout_endpoints:
            properties.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.TEMPORAL,
                    formal_statement=(
                        "Session tokens must be invalidated server-side on logout "
                        "and rejected for subsequent requests"
                    ),
                    model_nodes=[ep.id for ep in auth_endpoints[:3]] +
                                [ep.id for ep in logout_endpoints[:1]],
                    inference_confidence=0.8,
                    source_observations=[],
                )
            )

        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        """Génère des hypothèses de token replay pour les sessions."""
        hypotheses: list[Hypothesis] = []

        # Chercher endpoints authentifiés
        auth_endpoints = [
            ep for ep in model.endpoints
            if ep.auth_required or ep.roles_observed
        ][:3]  # Limiter à 3

        # Chercher endpoints de logout
        logout_endpoints = [
            ep for ep in model.endpoints
            if any(kw in ep.path.lower() for kw in LOGOUT_KEYWORDS)
        ]

        if not auth_endpoints or not logout_endpoints:
            return hypotheses

        logout_path = logout_endpoints[0].path

        for auth_ep in auth_endpoints:
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le token de session reste valide après logout et permet "
                        f"d'accéder à '{auth_ep.path}'"
                    ),
                    priority="HIGH",
                    priority_rationale=(
                        "Token non-invalidé = session hijacking persistant après logout"
                    ),
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="token_reuse",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "authenticated_endpoint": auth_ep.path,
                                "logout_endpoint": logout_path,
                            },
                            description=(
                                f"Token reuse: access {auth_ep.path} after logout {logout_path}"
                            ),
                        )
                    ],
                )
            )

        return hypotheses
