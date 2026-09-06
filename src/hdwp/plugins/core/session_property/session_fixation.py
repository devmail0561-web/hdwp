# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SessionFixationPlugin: détecte la fixation de session (CWE-384)."""
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

LOGIN_PATH_PATTERNS = (
    "login", "signin", "authenticate", "auth/token",
    "oauth/token", "api/auth", "session/create",
)


class SessionFixationPlugin(HDWPPlugin):
    """Détecte la fixation de session sur les endpoints d'authentification."""

    @property
    def id(self) -> str:
        return "core.session_property.session_fixation"

    @property
    def name(self) -> str:
        return "Session Fixation"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "session_property"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A07:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-384"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        login_endpoints = [
            ep for ep in model.endpoints
            if any(p in ep.path.lower() for p in LOGIN_PATH_PATTERNS)
        ]
        if not login_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.TEMPORAL,
            formal_statement="Session ID must be regenerated after successful authentication",
            model_nodes=[ep.id for ep in login_endpoints[:2]],
            inference_confidence=0.75,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        login_endpoints = [
            ep for ep in model.endpoints
            if any(p in ep.path.lower() for p in LOGIN_PATH_PATTERNS)
        ][:2]
        if not login_endpoints:
            return []
        hyps = []
        for ep in login_endpoints:
            method = next(
                (m for m in ep.methods if m in ("POST", "PUT")),
                ep.methods[0] if ep.methods else "POST",
            )
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"L'endpoint '{ep.path}' ne régénère pas l'identifiant de session "
                    f"après authentification"
                ),
                priority="HIGH",
                priority_rationale="Session fixation = prise de contrôle de session après login",
                required_experiments=[ExperimentSpec(
                    mutation_type="token_reuse",
                    base_request=NormalizedRequest(method=method, url=""),
                    mutation_params={
                        "login_endpoint": ep.path,
                        "attack_type": "session_fixation",
                    },
                    description=f"Session fixation probe sur {ep.path}",
                )],
            ))
        return hyps
