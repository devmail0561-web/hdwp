# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MassAssignmentPlugin: détecte les vulnérabilités de mass assignment / over-posting.

Réutilise field_injection avec payload_type='mass_assign'.
Détection via InjectionOracle.assess_mass_assignment() existant.
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

PRIVILEGED_FIELDS = [
    "role", "is_admin", "admin", "is_staff", "balance",
    "credit", "verified", "account_type",
]


class MassAssignmentPlugin(HDWPPlugin):
    """Détecte les vulnérabilités de mass assignment sur les endpoints POST/PUT/PATCH."""

    @property
    def id(self) -> str:
        return "core.injection.mass_assignment"

    @property
    def name(self) -> str:
        return "Mass Assignment Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A08:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-915"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        # Trouver les endpoints mutation avec paramètres body
        mutation_endpoints = [
            ep for ep in model.endpoints
            if any(m in ("POST", "PUT", "PATCH") for m in ep.methods)
        ]
        body_params = [
            p for p in model.parameters
            if p.location == "body"
        ]
        if not mutation_endpoints or not body_params:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement=(
                    "endpoint does not accept unexpected fields that alter authorization or state"
                ),
                model_nodes=[ep.id for ep in mutation_endpoints[:5]],
                inference_confidence=0.75,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        # Endpoints POST/PUT/PATCH avec au moins un paramètre body
        mutation_endpoints = [
            ep for ep in model.endpoints
            if any(m in ("POST", "PUT", "PATCH") for m in ep.methods)
        ]
        body_param_ids = {p.id for p in model.parameters if p.location == "body"}

        candidates = [
            ep for ep in mutation_endpoints
            if any(pid in body_param_ids for pid in ep.parameters)
        ][:3]

        hypotheses = []
        for ep in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={
                        "payload": "true",
                        "payload_type": "mass_assign",
                        "extra_field": field_name,
                        "parameter_location": "body",
                        "parameter_name": "",
                    },
                    description=f"Mass assignment test: inject {field_name}=true",
                )
                for field_name in PRIVILEGED_FIELDS[:4]
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"L'endpoint '{ep.path}' accepte des champs privilégiés non autorisés",
                    priority="HIGH",
                    priority_rationale="Mass assignment permet l'élévation de privilèges",
                    required_experiments=experiments,
                )
            )
        return hypotheses
