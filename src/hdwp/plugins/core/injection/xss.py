# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
XSSPlugin: détecte les vulnérabilités Cross-Site Scripting.

Réutilise la mutation field_injection avec payload_type='xss'.
Détection via InjectionOracle.assess_xss() existant.
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

# Mots-clés indiquant des champs reflétés dans HTML
XSS_PARAM_KEYWORDS = frozenset({
    "name", "comment", "message", "title", "description", "text",
    "content", "body", "search", "query", "feedback", "review",
})

# Payloads XSS classiques
XSS_PAYLOADS = [
    "<script>alert(1)</script>",                             # direct reflection
    "<img src=x onerror=alert(1)>",                         # inline event handler
    "<svg onload=alert(1)>",                                 # SVG vector
    '"><script>alert(1)</script>',                           # break out of attribute
    "' onmouseover='alert(1)",                               # attribute injection
    "<script>alert(String.fromCharCode(88,83,83))</script>", # encoded char bypass
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",                  # URL-encoded
    "<iframe src=\"javascript:alert(1)\">",                  # iframe js protocol
]


class XSSPlugin(HDWPPlugin):
    """Détecte les vulnérabilités Cross-Site Scripting."""

    @property
    def id(self) -> str:
        return "core.injection.xss"

    @property
    def name(self) -> str:
        return "XSS Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A03:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-79"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Infère des propriétés INTEGRITY pour les paramètres reflétés."""
        properties: list[SecurityProperty] = []

        # Chercher paramètres de contenu utilisateur
        xss_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in XSS_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]

        if xss_params:
            properties.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.INTEGRITY,
                    formal_statement=(
                        "User input reflected in HTML must be properly encoded to prevent XSS"
                    ),
                    model_nodes=[p.id for p in xss_params[:5]],
                    inference_confidence=0.75,
                    source_observations=[],
                )
            )

        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        """Génère des hypothèses XSS pour les paramètres candidats."""
        hypotheses: list[Hypothesis] = []

        # Paramètres candidats avec filtrage sémantique + contexte endpoint
        # XSS pertinent seulement si la réponse est HTML ou sans content-type connu
        EXCLUDED_SEMANTICS = frozenset({"id_ref", "file_path", "url_redirect", "credential"})
        candidates = [
            p for p in model.parameters
            if p.type_inferred == "string"
            and getattr(p, 'semantic', None) not in EXCLUDED_SEMANTICS
            and p.affects_object is None
            and (
                getattr(p, 'semantic', None) is None
                or any(kw in p.name.lower() for kw in XSS_PARAM_KEYWORDS)
            )
        ][:5]

        for param in candidates:
            # Trouver l'endpoint et vérifier si la réponse est HTML-compatible
            endpoints = [ep for ep in model.endpoints if param.id in ep.parameters]
            ep_path = endpoints[0].path if endpoints else ""
            content_type = getattr(endpoints[0], 'response_content_type', None) if endpoints else None
            # Skip si content-type est JSON pur (XSS peu pertinent)
            if content_type and "json" in content_type.lower() and "html" not in content_type.lower():
                continue

            experiments: list[ExperimentSpec] = []
            for payload in XSS_PAYLOADS[:3]:
                experiments.append(
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "xss",
                            "endpoint_path": ep_path,
                        },
                        description=f"XSS test: {param.name}={payload[:30]}",
                    )
                )

            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"[{ep_path}] Le paramètre '{param.name}' est vulnérable à XSS (payload reflété non-encodé)"
                    ),
                    priority="HIGH",
                    priority_rationale="XSS permet vol de sessions et exécution de code côté client",
                    required_experiments=experiments,
                )
            )

        return hypotheses
