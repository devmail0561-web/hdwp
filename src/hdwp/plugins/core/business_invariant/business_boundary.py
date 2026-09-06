# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
BusinessBoundaryPlugin: détecte les violations de logique métier (valeurs négatives,
débordement d'entier, manipulation de prix/quantités).

Réutilise field_injection avec payload_type='boundary'.
Détection via InjectionOracle.assess_business_boundary() existant.
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

FINANCIAL_KEYWORDS = frozenset({
    "price", "amount", "quantity", "total", "balance", "fee",
    "discount", "cost", "credit", "debit", "sum",
})

BOUNDARY_PAYLOADS = ["-1", "-9999", "0", "0.001", "9999999", "2147483647"]


class BusinessBoundaryPlugin(HDWPPlugin):
    """Détecte les violations de logique métier sur les paramètres financiers."""

    @property
    def id(self) -> str:
        return "core.business_invariant.business_boundary"

    @property
    def name(self) -> str:
        return "Business Boundary Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "business_invariant"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A04:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-840"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        financial_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in FINANCIAL_KEYWORDS)
            and p.type_inferred in ("integer", "string")
        ]
        if not financial_params:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.COHERENCE,
                formal_statement=(
                    "business invariant: financial parameters must be positive "
                    "and within a valid business range"
                ),
                model_nodes=[p.id for p in financial_params[:5]],
                inference_confidence=0.8,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        # Paramètres financiers sur endpoints POST/PUT/PATCH
        mutation_endpoint_paths = {
            ep.path for ep in model.endpoints
            if any(m in ("POST", "PUT", "PATCH") for m in ep.methods)
        }
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in FINANCIAL_KEYWORDS)
            and p.type_inferred in ("integer", "string")
        ][:5]

        hypotheses = []
        for param in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={
                        "payload": payload,
                        "payload_type": "boundary",
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                    },
                    description=f"Business boundary: {param.name}={payload}",
                )
                for payload in BOUNDARY_PAYLOADS[:4]
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre financier '{param.name}' accepte des valeurs non valides",
                    priority="HIGH",
                    priority_rationale="Manipulation de valeurs financières → fraude directe",
                    required_experiments=experiments,
                )
            )
        return hypotheses
