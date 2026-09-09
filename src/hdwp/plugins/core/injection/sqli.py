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

# Phase 1: Mapping ADAPTIVE_CHAINS pour PayloadDatabase
# Mappe les variant IDs (depuis sqli_payloads.yaml) aux triggers et follow-ups
ADAPTIVE_CHAINS = {
    "boolean_blind": {
        "trigger": {"or": [
            {"type": "body_matches_any", "value": [
                "syntax error", "SQL", "mysql", "ORA-", "PostgreSQL", "MSSQL",
                "sqlite", "Warning:", "You have an error",
            ]},
            {"type": "status_code", "operator": "==", "value": 500},
        ]},
        "follow_ups": ["union_basic", "union_waf_bypass"],
    },
    "time_based_mysql": {
        "trigger": {"type": "timing_ms", "operator": ">", "value": 4000},
        "follow_ups": ["time_based_mssql", "time_based_postgres"],
    },
    "comment_bypass": {
        "trigger": {"type": "status_code", "operator": "==", "value": 200},
        "follow_ups": ["url_encoded_bypass"],
    },
}

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

    def _build_adaptive_experiments(
        self,
        param: "Parameter",
        ep_path: str,
        variants: list["PayloadVariant"],
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

        # Grouper variants par ID de base (sans suffixes _encoded_*)
        variants_by_base_id = {}
        for variant in variants:
            base_id = variant.id.split("_encoded_")[0].split("_obfuscated_")[0]
            if base_id not in variants_by_base_id:
                variants_by_base_id[base_id] = []
            variants_by_base_id[base_id].append(variant)

        # Construire chaînes adaptatives
        for base_id, variant_list in variants_by_base_id.items():
            if base_id not in ADAPTIVE_CHAINS:
                # Pas de chaîne adaptative définie → expériment simple
                for variant in variant_list[:3]:  # Limiter à 3 variantes par base
                    experiments.append(
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": variant.value,
                                "payload_type": "sqli",
                                "endpoint_path": ep_path,
                            },
                            description=f"SQLi test: {param.name}={variant.id}",
                        )
                    )
                continue

            # Récupérer mapping adaptif
            adaptive_mapping = ADAPTIVE_CHAINS[base_id]
            trigger_condition = adaptive_mapping["trigger"]
            follow_up_ids = adaptive_mapping["follow_ups"]

            # Construire follow-up specs depuis IDs
            follow_up_specs = []
            for follow_up_id in follow_up_ids:
                follow_up_variants = variants_by_base_id.get(follow_up_id, [])
                for fv in follow_up_variants[:2]:  # 2 variantes max par follow-up
                    follow_up_specs.append(
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": fv.value,
                                "payload_type": "sqli",
                                "endpoint_path": ep_path,
                            },
                            description=f"SQLi follow-up: {fv.id}",
                        )
                    )

            # Créer sonde racine avec trigger + follow-ups
            root_variant = variant_list[0]  # Première variante comme racine
            experiments.append(
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                        "payload": root_variant.value,
                        "payload_type": "sqli",
                        "endpoint_path": ep_path,
                    },
                    description=f"SQLi probe: {base_id} {param.name}",
                    trigger_condition=trigger_condition,
                    follow_up_specs=follow_up_specs,
                )
            )

        return experiments

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

            # Fallback vers _sqli_chain() legacy si PayloadDatabase indisponible
            if not experiments:
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
