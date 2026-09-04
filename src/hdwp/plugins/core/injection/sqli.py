# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SQLiPlugin: détecte les vulnérabilités d'injection SQL.

Réutilise la mutation field_injection avec payload_type='sqli'.
Détection via InjectionOracle.assess_sqli() existant.
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

# Mots-clés indiquant des paramètres suspects pour SQLi
SQL_PARAM_KEYWORDS = frozenset({
    "id", "search", "query", "filter", "where", "order", "sort",
    "name", "user", "username", "email", "keyword", "term",
})

# Payloads SQLi classiques
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' AND 1=0 UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
]


class SQLiPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection SQL."""

    @property
    def id(self) -> str:
        return "core.injection.sqli"

    @property
    def name(self) -> str:
        return "SQL Injection Detection"

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
        return ["CWE-89"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Infère des propriétés INTEGRITY pour les paramètres SQL-sensibles."""
        properties: list[SecurityProperty] = []

        # Chercher paramètres avec mots-clés SQL
        sql_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in SQL_PARAM_KEYWORDS)
            and p.type_inferred in ("string", "integer")
        ]

        if sql_params:
            properties.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.INTEGRITY,
                    formal_statement=(
                        "Database queries must sanitize user input to prevent SQL injection"
                    ),
                    model_nodes=[p.id for p in sql_params[:5]],
                    inference_confidence=0.7,
                    source_observations=[],
                )
            )

        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        """Génère des hypothèses SQLi pour les paramètres candidats."""
        hypotheses: list[Hypothesis] = []

        # Paramètres candidats
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in SQL_PARAM_KEYWORDS)
            and p.type_inferred in ("string", "integer")
        ][:5]  # Limiter à 5 pour éviter explosion

        for param in candidates:
            # Créer une hypothèse avec plusieurs payloads
            experiments: list[ExperimentSpec] = []
            for payload in SQLI_PAYLOADS[:3]:  # Top 3 payloads
                experiments.append(
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "sqli",
                        },
                        description=f"SQLi test: {param.name}={payload[:30]}",
                    )
                )

            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le paramètre '{param.name}' est vulnérable à l'injection SQL"
                    ),
                    priority="HIGH",
                    priority_rationale="SQLi permet accès/modification base de données",
                    required_experiments=experiments,
                )
            )

        return hypotheses
