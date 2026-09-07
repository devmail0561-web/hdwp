# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Laravel mass assignment — activé si framework:laravel détecté."""
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

# Champs Eloquent typiquement fillable par erreur en Laravel
_LARAVEL_PROTECTED_FIELDS = [
    "is_admin", "admin", "role", "email_verified_at",
    "password", "remember_token", "api_token",
    "stripe_id", "subscription", "plan",
    "verified", "active", "blocked", "status",
]


class LaravelMassAssignPlugin(HDWPPlugin):
    """Détecte le mass assignment sur les modèles Eloquent Laravel."""

    @property
    def id(self) -> str:
        return "core.authorization.laravel_mass_assign"

    @property
    def name(self) -> str:
        return "Laravel Mass Assignment"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "authorization"

    def tech_stack_required(self) -> set[str]:
        return {"framework:laravel", "framework:php"}

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        write_endpoints = [
            ep for ep in model.endpoints
            if any(m in {"PUT", "PATCH", "POST"} for m in ep.methods)
        ]
        if not write_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement="Laravel Eloquent mass assignment: writable endpoints may accept protected fields",
            model_nodes=[ep.id for ep in write_endpoints],
            inference_confidence=0.78,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        write_endpoints = [
            ep for ep in model.endpoints
            if any(m in {"PUT", "PATCH"} for m in ep.methods)
        ][:4]
        hypotheses = []
        for ep in write_endpoints:
            method = next((m for m in ep.methods if m in {"PUT", "PATCH"}), "PUT")
            for field in _LARAVEL_PROTECTED_FIELDS[:4]:
                hypotheses.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"[Laravel MassAssign] {ep.path} — injecter {field}",
                    priority="HIGH",
                    priority_rationale="Laravel Eloquent mass assignment sur champ protégé",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method=method, url=ep.path),
                        mutation_params={
                            "parameter_name": field,
                            "parameter_location": "body",
                            "payload": "1",
                            "payload_type": "mass_assign",
                            "endpoint_path": ep.path,
                        },
                        description=f"Laravel mass assignment: {method} {ep.path} + {field}=1",
                    )],
                ))
        return hypotheses

    def register_mutations(self) -> list[dict]:
        return []
