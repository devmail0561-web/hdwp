# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""CSRFPlugin: Cross-Site Request Forgery detection (CWE-352)."""
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

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class CSRFPlugin(HDWPPlugin):
    """Détecte l'absence de protection CSRF sur les endpoints d'écriture."""

    @property
    def id(self) -> str:
        return "core.authorization.csrf"

    @property
    def name(self) -> str:
        return "Cross-Site Request Forgery (CSRF)"

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
        return ["CWE-352"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        write_endpoints = [
            ep for ep in model.endpoints
            if any(m in WRITE_METHODS for m in ep.methods) and ep.auth_required
        ]
        if not write_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.AUTHORIZATION,
            formal_statement="State-changing endpoints must require a CSRF token",
            model_nodes=[ep.id for ep in write_endpoints[:3]],
            inference_confidence=0.7,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        write_endpoints = [
            ep for ep in model.endpoints
            if any(m in WRITE_METHODS for m in ep.methods) and ep.auth_required
        ][:5]
        if not write_endpoints:
            return []
        hyps = []
        for ep in write_endpoints:
            method = next((m for m in ep.methods if m in WRITE_METHODS), "POST")
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=(
                    f"L'endpoint '{ep.path}' [{method}] est vulnérable au CSRF "
                    f"— pas de token requis"
                ),
                priority="MEDIUM",
                priority_rationale="CSRF = actions non-autorisées via navigateur authentifié",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method=method, url=""),
                    mutation_params={
                        "endpoint_path": ep.path,
                        "remove_csrf_token": "true",
                        "payload_type": "csrf_probe",
                    },
                    description=f"CSRF test: requête {method} sans CSRF token sur {ep.path}",
                )],
            ))
        return hyps
