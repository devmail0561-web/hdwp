# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
JWTPlugin: détecte les vulnérabilités de validation JWT.

Stratégies testées :
1. alg:none — supprimer la signature, changer alg à "none"
2. Expiration non vérifiée — rejouer un token expiré (exp dans le passé)
3. Secret faible — tenter une liste de secrets communs (HS256 uniquement)

Prérequis : au moins un endpoint avec rôle authentifié (Bearer).
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

_JWT_ATTACKS = [
    ("alg_none", "JWT alg:none — forger un token sans signature"),
    ("expired_token", "JWT exp passé — rejouer un token expiré"),
    ("weak_secret", "JWT secret faible — brute-force HS256"),
]


class JWTPlugin(HDWPPlugin):
    """Détecte les failles de validation JWT."""

    @property
    def id(self) -> str:
        return "core.session_property.jwt"

    @property
    def name(self) -> str:
        return "JWT Validation Weaknesses"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "session_property"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A02:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-347", "CWE-613"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        auth_endpoints = [ep for ep in model.endpoints if ep.auth_required or ep.roles_observed]
        if not auth_endpoints:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.TEMPORAL,
                formal_statement=(
                    "JWT tokens must be validated: algorithm, signature, and expiration"
                ),
                model_nodes=[ep.id for ep in auth_endpoints[:3]],
                inference_confidence=0.65,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        auth_endpoints = [ep for ep in model.endpoints if ep.auth_required or ep.roles_observed]
        if not auth_endpoints:
            return []

        hyps: list[Hypothesis] = []
        # Tester TOUS les endpoints authentifiés (pas seulement le premier), limité à 10
        for target_ep in auth_endpoints[:10]:
            for attack, description in _JWT_ATTACKS:
                hyps.append(
                    Hypothesis(
                        source_plugin=self.id,
                        property_id="",
                        statement=f"JWT {attack} sur '{target_ep.path}': {description} accepté",
                        priority="HIGH",
                        priority_rationale="Faille JWT = bypass d'authentification complet",
                        required_experiments=[
                            ExperimentSpec(
                                mutation_type="jwt_manipulation",
                                base_request=NormalizedRequest(method="GET", url=""),
                                mutation_params={
                                    "jwt_attack": attack,
                                    "target_endpoint": target_ep.path,
                                },
                                description=description,
                            )
                        ],
                    )
                )
        return hyps
