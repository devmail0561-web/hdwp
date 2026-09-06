# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
NoSQLiPlugin: détecte les vulnérabilités d'injection NoSQL (MongoDB et similaires).

IMPORTANT: les payloads sont stockés comme dicts Python (pas des strings)
pour que apply_field_injection() les injecte correctement comme objets JSON.
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

NOSQL_PARAM_KEYWORDS = frozenset({
    "username", "user", "email", "password", "login",
    "filter", "query", "search", "id",
})

# Payloads NoSQL — dicts Python pour injection objet JSON correcte dans MongoDB
NOSQLI_PAYLOADS: list[dict | str] = [
    {"$gt": ""},           # bypass auth: username[$gt]=""
    {"$regex": ".*"},      # wildcard match
    {"$where": "1==1"},    # JavaScript injection (MongoDB)
    "[$ne]=1",             # form-style pour query string
]


class NoSQLiPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection NoSQL."""

    @property
    def id(self) -> str:
        return "core.injection.nosqli"

    @property
    def name(self) -> str:
        return "NoSQL Injection Detection"

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
        return ["CWE-943"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in NOSQL_PARAM_KEYWORDS)
            and p.type_inferred in ("string", "object")
        ]
        if not candidates:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement="NoSQL queries must sanitize operator injection from user input",
                model_nodes=[p.id for p in candidates[:5]],
                inference_confidence=0.7,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in NOSQL_PARAM_KEYWORDS)
            and p.type_inferred in ("string", "object")
        ][:5]

        hypotheses = []
        for param in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={
                        "payload": payload,   # dict pour les 3 premiers, string pour le dernier
                        "payload_type": "nosqli",
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                    },
                    description=f"NoSQLi test: {param.name}={str(payload)[:30]}",
                )
                for payload in NOSQLI_PAYLOADS
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' est vulnérable à l'injection NoSQL",
                    priority="HIGH",
                    priority_rationale="NoSQLi permet le bypass d'authentification",
                    required_experiments=experiments,
                )
            )
        return hypotheses
