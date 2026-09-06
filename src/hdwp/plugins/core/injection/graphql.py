# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""GraphQLPlugin: détecte les failles de sécurité spécifiques à GraphQL."""
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

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")

INTROSPECTION_QUERY = '{"query": "{ __schema { types { name fields { name } } } }"}'
BATCH_QUERY = '[{"query": "{ user(id: 1) { email } }"}, {"query": "{ user(id: 2) { email } }"}, {"query": "{ user(id: 3) { email } }"}]'
DEPTH_QUERY = '{"query": "{ user { friends { friends { friends { friends { friends { id } } } } } } }"}'


class GraphQLPlugin(HDWPPlugin):
    """Détecte les failles GraphQL: introspection exposée, batching, injection de variables."""

    @property
    def id(self) -> str:
        return "core.injection.graphql"

    @property
    def name(self) -> str:
        return "GraphQL Security"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A03:2021", "A05:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-200", "CWE-284"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        gql_endpoints = [
            ep for ep in model.endpoints
            if getattr(ep, "is_graphql", False)
            or any(gp in ep.path.lower() for gp in GRAPHQL_PATHS)
        ]
        if not gql_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.CONFIDENTIALITY,
            formal_statement="GraphQL endpoints must disable introspection in production and limit query depth/batching",
            model_nodes=[ep.id for ep in gql_endpoints[:2]],
            inference_confidence=0.85,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        gql_endpoints = [
            ep for ep in model.endpoints
            if getattr(ep, "is_graphql", False)
            or any(gp in ep.path.lower() for gp in GRAPHQL_PATHS)
        ]
        if not gql_endpoints:
            return []

        hyps: list[Hypothesis] = []
        for ep in gql_endpoints[:2]:
            hyps.append(Hypothesis(
                source_plugin=self.id, property_id="",
                statement=f"GraphQL '{ep.path}': introspection activée en production",
                priority="HIGH",
                priority_rationale="Introspection expose le schéma complet aux attaquants",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={"parameter_name": "query", "parameter_location": "body", "payload": INTROSPECTION_QUERY, "payload_type": "graphql_introspection"},
                    description=f"GraphQL introspection sur {ep.path}",
                )],
            ))
            hyps.append(Hypothesis(
                source_plugin=self.id, property_id="",
                statement=f"GraphQL '{ep.path}': batching non limité — énumération possible",
                priority="MEDIUM",
                priority_rationale="Batching permet contournement rate-limit et énumération massive",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={"parameter_name": "query", "parameter_location": "body", "payload": BATCH_QUERY, "payload_type": "graphql_batch"},
                    description=f"GraphQL batch query sur {ep.path}",
                )],
            ))
            hyps.append(Hypothesis(
                source_plugin=self.id, property_id="",
                statement=f"GraphQL '{ep.path}': profondeur de requête non limitée — DoS possible",
                priority="MEDIUM",
                priority_rationale="Requêtes profondes provoquent DoS ou information disclosure",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="POST", url=""),
                    mutation_params={"parameter_name": "query", "parameter_location": "body", "payload": DEPTH_QUERY, "payload_type": "graphql_depth"},
                    description=f"GraphQL depth attack sur {ep.path}",
                )],
            ))
        return hyps
