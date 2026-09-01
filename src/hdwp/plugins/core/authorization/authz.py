# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

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


class AuthZPlugin(HDWPPlugin):
    """Detects authorization bypass vulnerabilities."""

    @property
    def id(self) -> str:
        return "core.authorization.authz"

    @property
    def name(self) -> str:
        return "Authorization Bypass Detection"

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
        properties: list[SecurityProperty] = []
        for ep in model.endpoints:
            if ep.auth_required and ep.roles_observed:
                properties.append(
                    SecurityProperty(
                        type=PropertyType.AUTHORIZATION,
                        formal_statement=(
                            f"AuthZ: endpoint '{ep.path}' restricted to roles "
                            f"{ep.roles_observed}"
                        ),
                        model_nodes=[ep.id],
                        inference_confidence=0.8,
                    )
                )
        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        roles = model.roles
        if len(roles) < 2:
            return hypotheses
        for ep in model.endpoints:
            if ep.auth_required and ep.roles_observed:
                for role in roles:
                    if role.name not in ep.roles_observed and role.name != "anonymous":
                        hypotheses.append(
                            Hypothesis(
                                source_plugin=self.id,
                                property_id="",
                                statement=(
                                    f"Endpoint '{ep.path}' can be accessed by "
                                    f"unauthorized role '{role.name}'"
                                ),
                                priority="HIGH",
                                priority_rationale="Authorization bypass: accessing restricted functionality",
                                required_experiments=[
                                    ExperimentSpec(
                                        mutation_type="privilege_escalation",
                                        base_request=NormalizedRequest(
                                            method=ep.methods[0] if ep.methods else "GET",
                                            url="",
                                        ),
                                        mutation_params={
                                            "endpoint_path": ep.path,
                                            "target_role": role.name,
                                        },
                                        description=(
                                            f"Access '{ep.path}' with role '{role.name}' credentials"
                                        ),
                                    ),
                                ],
                            )
                        )
        return hypotheses
