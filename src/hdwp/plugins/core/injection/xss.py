# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
XSSPlugin: détecte les vulnérabilités Cross-Site Scripting.

Réutilise la mutation field_injection avec payload_type='xss'.
Détection via InjectionOracle.assess_xss() existant.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from hdwp.store.payload_database import PayloadDatabase

# Mots-clés indiquant des champs reflétés dans HTML
XSS_PARAM_KEYWORDS = frozenset({
    "name", "comment", "message", "title", "description", "text",
    "content", "body", "search", "query", "feedback", "review",
})

# Phase 1: Mapping ADAPTIVE_CHAINS pour PayloadDatabase
# Mappe les variant IDs (depuis xss_payloads.yaml) aux triggers et follow-ups
ADAPTIVE_CHAINS = {
    "script_basic": {
        "trigger": {"type": "body_not_contains", "value": "<script>alert(1)"},
        "follow_ups": ["encoded_payload", "event_handlers", "polyglot"],
    },
    "img_onerror": {
        "trigger": {"type": "body_not_contains", "value": "onerror"},
        "follow_ups": ["svg_onload", "attribute_breakout"],
    },
}

# Payloads XSS legacy — utilisés en fallback si PayloadDatabase indisponible (Phase 0)
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

    def __init__(self, payload_db: "PayloadDatabase | None" = None):
        """Phase 0: injection PayloadDatabase pour externalisation payloads."""
        self._payload_db = payload_db

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

    def _build_adaptive_experiments(
        self,
        param: "Parameter",  # noqa: F821
        ep_path: str,
        variants: list["PayloadVariant"],  # noqa: F821
    ) -> list[ExperimentSpec]:
        """Construit ExperimentSpec avec trigger_condition + follow_up_specs.

        Phase 1: Utilise PayloadDatabase variants avec mapping ADAPTIVE_CHAINS.

        Args:
            param: Paramètre cible
            ep_path: Path de l'endpoint
            variants: PayloadVariant depuis PayloadDatabase (avec auto-encoding)

        Returns:
            Liste d'ExperimentSpec avec logique adaptative
        """
        experiments = []

        # Grouper variants par ID de base
        variants_by_base_id = {}
        for variant in variants:
            base_id = variant.id.split("_encoded_")[0].split("_obfuscated_")[0]
            if base_id not in variants_by_base_id:
                variants_by_base_id[base_id] = []
            variants_by_base_id[base_id].append(variant)

        # Construire chaînes adaptatives
        for base_id, variant_list in variants_by_base_id.items():
            if base_id not in ADAPTIVE_CHAINS:
                # Pas de chaîne adaptative → expériment simple
                for variant in variant_list[:3]:
                    experiments.append(
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": variant.value,
                                "payload_type": "xss",
                                "endpoint_path": ep_path,
                            },
                            description=f"XSS test: {param.name}={variant.id}",
                        )
                    )
                continue

            # Récupérer mapping adaptif
            adaptive_mapping = ADAPTIVE_CHAINS[base_id]
            trigger_condition = adaptive_mapping["trigger"]
            follow_up_ids = adaptive_mapping["follow_ups"]

            # Construire follow-up specs
            follow_up_specs = []
            for follow_up_id in follow_up_ids:
                follow_up_variants = variants_by_base_id.get(follow_up_id, [])
                for fv in follow_up_variants[:2]:
                    follow_up_specs.append(
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": fv.value,
                                "payload_type": "xss",
                                "endpoint_path": ep_path,
                            },
                            description=f"XSS follow-up: {fv.id}",
                        )
                    )

            # Créer sonde racine avec trigger + follow-ups
            root_variant = variant_list[0]
            experiments.append(
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                        "payload": root_variant.value,
                        "payload_type": "xss",
                        "endpoint_path": ep_path,
                    },
                    description=f"XSS probe: {base_id} {param.name}",
                    trigger_condition=trigger_condition,
                    follow_up_specs=follow_up_specs,
                )
            )

        return experiments

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

            experiments = []

            # Phase 1: Charger depuis PayloadDatabase avec auto-encoding/obfuscation
            if self._payload_db:
                payload_variants = self._payload_db.get_payloads(
                    self.id,
                    tech_stack=model.tech_stack,
                    auto_encode=True,       # Activer auto-encoding
                    auto_obfuscate=True,    # Activer auto-obfuscation
                    max_variants=20
                )

                # Construire chaînes adaptatives depuis PayloadDatabase
                if payload_variants:
                    experiments = self._build_adaptive_experiments(
                        param, ep_path, payload_variants
                    )

            # Fallback vers chaîne adaptative legacy inline
            if not experiments:
                # Chaîne adaptative XSS :
                # Sonde 1 : payload brut → si réfléchi tel quel → CONFIRMED
                # Si filtré (body_not_contains) → essayer les variantes encodées/bypass
                sonde_basic = ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param.name, "parameter_location": param.location,
                    "payload": "<script>alert(1)</script>",
                    "payload_type": "xss", "endpoint_path": ep_path,
                },
                description=f"XSS probe: {param.name} basic",
                trigger_condition={"type": "body_not_contains", "value": "<script>alert(1)"},
                follow_up_specs=[
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name, "parameter_location": param.location,
                            "payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                            "payload_type": "xss", "endpoint_path": ep_path,
                        },
                        description=f"XSS URL-encoded: {param.name}",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name, "parameter_location": param.location,
                            "payload": "<img src=x onerror=alert(1)>",
                            "payload_type": "xss", "endpoint_path": ep_path,
                        },
                        description=f"XSS img onerror: {param.name}",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name, "parameter_location": param.location,
                            "payload": "javascript:alert(1)",
                            "payload_type": "xss", "endpoint_path": ep_path,
                        },
                        description=f"XSS javascript: {param.name}",
                    ),
                ],
            )
                experiments = [sonde_basic]

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
