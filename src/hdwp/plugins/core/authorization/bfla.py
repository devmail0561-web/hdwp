# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""BFLAPlugin: Broken Function Level Authorization (CWE-285)."""
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

# Patterns d'endpoints à accès restreint
ADMIN_PATH_PATTERNS = (
    "/admin", "/manage", "/internal", "/staff", "/superuser",
    "/api/admin", "/api/management", "/api/internal", "/dashboard/admin",
    "/v1/admin", "/v2/admin", "/system", "/ops", "/operator",
)


class BFLAPlugin(HDWPPlugin):
    """Détecte le Broken Function Level Authorization (BFLA)."""

    @property
    def id(self) -> str:
        return "core.authorization.bfla"

    @property
    def name(self) -> str:
        return "Broken Function Level Authorization (BFLA)"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "authorization"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021", "API5:2023"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-285"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        admin_endpoints = [
            ep for ep in model.endpoints
            if any(p in ep.path.lower() for p in ADMIN_PATH_PATTERNS)
        ]
        if not admin_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.AUTHORIZATION,
            formal_statement="Administrative functions must enforce role-based access control",
            model_nodes=[ep.id for ep in admin_endpoints[:3]],
            inference_confidence=0.8,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        admin_endpoints = [
            ep for ep in model.endpoints
            if any(p in ep.path.lower() for p in ADMIN_PATH_PATTERNS)
        ][:5]
        if not admin_endpoints:
            return []
        roles = model.roles if model.roles else []
        non_admin_roles = [
            r for r in roles
            if "admin" not in r.name.lower() and "staff" not in r.name.lower()
        ]
        target_role = non_admin_roles[0].name if non_admin_roles else "anonymous"
        hyps = []
        for ep in admin_endpoints:
            method = ep.methods[0] if ep.methods else "GET"
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=f"L'endpoint admin '{ep.path}' est accessible avec le rôle '{target_role}'",
                priority="HIGH",
                priority_rationale="BFLA = accès fonctions admin sans autorisation",
                required_experiments=[ExperimentSpec(
                    mutation_type="privilege_escalation",
                    base_request=NormalizedRequest(method=method, url=""),
                    mutation_params={
                        "endpoint_path": ep.path,
                        "target_role": target_role,
                    },
                    description=f"BFLA: accès à {ep.path} avec rôle {target_role}",
                )],
            ))
        return hyps
