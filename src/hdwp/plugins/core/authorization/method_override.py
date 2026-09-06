# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MethodOverridePlugin: détecte le bypass d'autorisation via HTTP method override.

Envoie GET + X-HTTP-Method-Override: DELETE sur des endpoints qui nécessitent
une méthode restreinte et une autorisation élevée.
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

RESTRICTED_METHODS = {"DELETE", "PUT", "PATCH"}


class MethodOverridePlugin(HDWPPlugin):
    """Détecte le bypass d'autorisation via HTTP method override."""

    @property
    def id(self) -> str:
        return "core.authorization.method_override"

    @property
    def name(self) -> str:
        return "HTTP Method Override Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "authorization"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-284"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        targets = [
            ep for ep in model.endpoints
            if ep.auth_required and any(m in RESTRICTED_METHODS for m in ep.methods)
        ]
        if not targets:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.AUTHORIZATION,
                formal_statement="server must not honour HTTP method override headers from unprivileged clients",
                model_nodes=[ep.id for ep in targets[:5]],
                inference_confidence=0.75,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        targets = [
            ep for ep in model.endpoints
            if ep.auth_required and any(m in RESTRICTED_METHODS for m in ep.methods)
        ][:5]

        hypotheses = []
        for ep in targets:
            for method in sorted(RESTRICTED_METHODS & set(ep.methods)):
                hypotheses.append(
                    Hypothesis(
                        source_plugin=self.id,
                        property_id="",
                        statement=(
                            f"L'endpoint '{ep.path}' autorise {method} "
                            "via X-HTTP-Method-Override depuis un rôle non autorisé"
                        ),
                        priority="HIGH",
                        priority_rationale="Method override contourne le contrôle d'accès HTTP",
                        required_experiments=[
                            ExperimentSpec(
                                mutation_type="method_override",
                                base_request=NormalizedRequest(method="GET", url=""),
                                mutation_params={
                                    "override_method": method,
                                    "endpoint_path": ep.path,
                                },
                                description=f"Method override: GET + X-HTTP-Method-Override: {method} on {ep.path}",
                            )
                        ],
                    )
                )
        return hypotheses
