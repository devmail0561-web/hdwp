# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SSTIPlugin: détecte les vulnérabilités Server-Side Template Injection.

Réutilise la mutation field_injection avec payload_type='ssti'.
Détection via InjectionOracle.assess_ssti() existant.
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

# Mots-clés indiquant des paramètres traités par templates
SSTI_PARAM_KEYWORDS = frozenset({
    "template", "view", "page", "render", "format", "layout",
    "theme", "skin", "widget", "content",
})

# Payloads SSTI avec résultats attendus
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("{7*7}", "49"),
    ("{{config}}", ""),  # Flask config object
]


class SSTIPlugin(HDWPPlugin):
    """Détecte les vulnérabilités Server-Side Template Injection."""

    @property
    def id(self) -> str:
        return "core.injection.ssti"

    @property
    def name(self) -> str:
        return "SSTI Detection"

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
        return ["CWE-94"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Infère des propriétés INTEGRITY pour les paramètres template-sensibles."""
        properties: list[SecurityProperty] = []

        # Chercher paramètres template-related
        ssti_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in SSTI_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]

        if ssti_params:
            properties.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.INTEGRITY,
                    formal_statement=(
                        "Template parameters must be sanitized to prevent server-side code execution"
                    ),
                    model_nodes=[p.id for p in ssti_params[:5]],
                    inference_confidence=0.65,
                    source_observations=[],
                )
            )

        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        """Génère des hypothèses SSTI pour les paramètres candidats."""
        hypotheses: list[Hypothesis] = []

        # Paramètres candidats
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in SSTI_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:5]

        for param in candidates:
            experiments: list[ExperimentSpec] = []

            for payload, expected in SSTI_PAYLOADS[:3]:
                experiments.append(
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "ssti",
                            "expected_result": expected,
                        },
                        description=f"SSTI test: {param.name}={payload}",
                    )
                )

            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le paramètre '{param.name}' est vulnérable à SSTI "
                        "(template évalué côté serveur)"
                    ),
                    priority="HIGH",
                    priority_rationale="SSTI permet exécution de code serveur arbitraire",
                    required_experiments=experiments,
                )
            )

        return hypotheses


# Phase 1: Mutation custom SSTI avec expected_result validation

def register_ssti_mutations() -> None:
    """Enregistre mutation custom ssti_evaluation dans MutationRegistry.

    Phase 1 optionnel: Améliore la détection SSTI en comparant le résultat
    avec expected_result (ex: {{7*7}} doit retourner "49").
    """
    from hdwp.core.mutation_registry import register_mutation

    def assess_ssti_evaluation(baseline, experiment, diff):
        """Assess SSTI par comparaison result vs expected_result."""
        from hdwp.core.oracle.violation_oracle import ViolationAssessment, ConfidenceLevel

        expected = experiment.mutation_params.get("expected_result")
        if not expected:
            # Pas d'expected_result → fallback vers assess_field_injection
            from hdwp.core.oracle.violation_oracle import _assess_field_injection
            return _assess_field_injection(baseline, experiment, diff)

        # Vérifier si expected_result présent dans body
        body = experiment.response_received.body or ""
        if expected in body:
            return ViolationAssessment(
                violated=True,
                confidence=ConfidenceLevel.HIGH,
                verdict=f"SSTI confirmed: template evaluated to expected result '{expected}'",
                evidence=[f"Expected '{expected}' found in response body"],
            )

        return ViolationAssessment(
            violated=False,
            confidence=ConfidenceLevel.LOW,
            verdict="SSTI not confirmed: expected result not found",
        )

    register_mutation(
        name="ssti_evaluation",
        owasp_category="A03:2021",
        cwe_id="CWE-94",
        remediation="Sanitize template parameters to prevent code execution",
        assess_violation=assess_ssti_evaluation,
    )


# Auto-registration au chargement du module
try:
    register_ssti_mutations()
except Exception:
    # Ignore si MutationRegistry pas encore initialisé
    pass
