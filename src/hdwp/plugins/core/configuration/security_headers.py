# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SecurityHeadersPlugin: détecte les security headers HTTP manquants (CWE-693)."""
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

REQUIRED_SECURITY_HEADERS = {
    "content-security-policy": "CSP absent — XSS aggravé",
    "strict-transport-security": "HSTS absent — MITM possible",
    "x-frame-options": "X-Frame-Options absent — Clickjacking possible",
    "x-content-type-options": "X-Content-Type-Options absent — MIME sniffing",
    "referrer-policy": "Referrer-Policy absent — fuite d'URL",
}

_NOISE_PATHS = ("/static/", "/assets/", "/.well-known/", "/favicon")


class SecurityHeadersPlugin(HDWPPlugin):
    """Détecte les security headers HTTP manquants sur les endpoints."""

    @property
    def id(self) -> str:
        return "core.configuration.security_headers"

    @property
    def name(self) -> str:
        return "Missing Security Headers"

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
        return ["CWE-693", "CWE-1021"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not model.endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.COHERENCE,
            formal_statement=(
                "HTTP responses must include security headers: "
                "CSP, HSTS, X-Frame-Options, X-Content-Type-Options"
            ),
            model_nodes=[ep.id for ep in model.endpoints[:5]],
            inference_confidence=0.9,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not model.endpoints:
            return []
        main_endpoints = [
            ep for ep in model.endpoints
            if not any(x in ep.path for x in _NOISE_PATHS)
        ][:3]
        hyps: list[Hypothesis] = []
        for ep in main_endpoints:
            for header, description in REQUIRED_SECURITY_HEADERS.items():
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"L'endpoint '{ep.path}' ne retourne pas le header "
                        f"'{header}' — {description}"
                    ),
                    priority="LOW",
                    priority_rationale="Security headers manquants = surface d'attaque élargie",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "endpoint_path": ep.path,
                            "check_header": header,
                            "payload_type": "security_header_check",
                        },
                        description=f"Vérifier présence {header} sur {ep.path}",
                    )],
                ))
        return hyps[:10]
