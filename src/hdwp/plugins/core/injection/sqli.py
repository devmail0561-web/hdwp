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

# Chaînes de payloads adaptatives — chaque sonde détermine les follow-ups
# La structure est : sonde → trigger_condition → follow_up_specs plus ciblés
# En cas de non-trigger : 1 seul experiment vs 9 auparavant (réduction du bruit)

def _sqli_chain(param_name: str, param_loc: str, ep_path: str) -> list[ExperimentSpec]:
    """Construit la chaîne adaptative SQLi pour un paramètre donné."""

    # Sonde 1 : détection d'erreur SQL (boolean + union detection)
    sonde_union = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url=""),
        mutation_params={
            "parameter_name": param_name, "endpoint_path": ep_path,
            "parameter_location": param_loc, "payload": "' OR '1'='1",
            "payload_type": "sqli",
        },
        description=f"SQLi probe: boolean blind {param_name}",
        trigger_condition={"or": [
            {"type": "body_matches_any", "value": [
                "syntax error", "SQL", "mysql", "ORA-", "PostgreSQL", "MSSQL",
                "sqlite", "Warning:", "You have an error",
            ]},
            {"type": "status_code", "operator": "==", "value": 500},
        ]},
        follow_up_specs=[
            # Enumération colonnes UNION
            ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param_name, "endpoint_path": ep_path,
                    "parameter_location": param_loc,
                    "payload": "1' UNION SELECT NULL,NULL,NULL--",
                    "payload_type": "sqli",
                },
                description=f"SQLi UNION 3-col: {param_name}",
            ),
            # WAF bypass
            ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param_name, "endpoint_path": ep_path,
                    "parameter_location": param_loc,
                    "payload": "1' OR 1=1/**/--",
                    "payload_type": "sqli",
                },
                description=f"SQLi WAF bypass: {param_name}",
            ),
        ],
    )

    # Sonde 2 : time-based MySQL → si timing > 4s, tester les variantes MSSQL et PostgreSQL
    sonde_timing = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url=""),
        mutation_params={
            "parameter_name": param_name, "endpoint_path": ep_path,
            "parameter_location": param_loc, "payload": "1' AND SLEEP(5)--",
            "payload_type": "sqli",
        },
        description=f"SQLi MySQL time-based: {param_name}",
        trigger_condition={"type": "timing_ms", "operator": ">", "value": 4000},
        follow_up_specs=[
            ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param_name, "endpoint_path": ep_path,
                    "parameter_location": param_loc,
                    "payload": "1' WAITFOR DELAY '0:0:5'--",
                    "payload_type": "sqli",
                },
                description=f"SQLi MSSQL time-based: {param_name}",
            ),
            ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param_name, "endpoint_path": ep_path,
                    "parameter_location": param_loc,
                    "payload": "1'; SELECT pg_sleep(5)--",
                    "payload_type": "sqli",
                },
                description=f"SQLi PostgreSQL time-based: {param_name}",
            ),
        ],
    )

    # Sonde 3 : bypass commentaire → si 200, essayer bypass URL-encoded
    sonde_comment = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url=""),
        mutation_params={
            "parameter_name": param_name, "endpoint_path": ep_path,
            "parameter_location": param_loc, "payload": "admin'--",
            "payload_type": "sqli",
        },
        description=f"SQLi comment bypass: {param_name}",
        trigger_condition={"type": "status_code", "operator": "==", "value": 200},
        follow_up_specs=[
            ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="GET", url=""),
                mutation_params={
                    "parameter_name": param_name, "endpoint_path": ep_path,
                    "parameter_location": param_loc,
                    "payload": "%27 OR %271%27%3D%271",
                    "payload_type": "sqli",
                },
                description=f"SQLi URL-encoded bypass: {param_name}",
            ),
        ],
    )

    return [sonde_union, sonde_timing, sonde_comment]


class SQLiPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection SQL."""

    def __init__(self, payload_db: "PayloadDatabase | None" = None):
        """Phase 0: injection PayloadDatabase (full integration Phase 1)."""
        self._payload_db = payload_db

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

        # Paramètres candidats — exclure les sémantiques déjà couverts par d'autres plugins
        # id_ref → BOLA ; file_path → path traversal ; url_redirect → SSRF ; credential → passif
        EXCLUDED_SEMANTICS = frozenset({"id_ref", "file_path", "url_redirect", "credential"})
        candidates = [
            p for p in model.parameters
            if p.type_inferred in ("string", "integer")
            and p.affects_object is None  # affects_object = BOLA, pas SQLi
            and getattr(p, 'semantic', None) not in EXCLUDED_SEMANTICS
            and (
                getattr(p, 'semantic', None) is None  # signal sémantique absent → fallback keywords
                or any(kw in p.name.lower() for kw in SQL_PARAM_KEYWORDS)
            )
        ][:5]

        for param in candidates:
            # Trouver les endpoints contenant ce paramètre
            endpoints = [ep for ep in model.endpoints if param.id in ep.parameters]
            ep_path = endpoints[0].path if endpoints else ""

            # Chaîne adaptative : 3 sondes racines avec follow-ups conditionnels
            # Réduit le trafic HTTP de 9 requêtes à 1-3 si non vulnérable
            experiments = _sqli_chain(param.name, param.location, ep_path)

            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"[{ep_path}] Le paramètre '{param.name}' est vulnérable à l'injection SQL"
                    ),
                    priority="HIGH",
                    priority_rationale="SQLi permet accès/modification base de données",
                    required_experiments=experiments,
                )
            )

        return hypotheses
