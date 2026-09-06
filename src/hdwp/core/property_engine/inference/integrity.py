# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
IntegrityInference: inférence des propriétés d'intégrité.

Règle : tout paramètre user-controlled est une surface d'injection potentielle.
Propriété inférée : "le paramètre P est traité comme une donnée, pas comme du code".

Règle mass assignment : un endpoint POST/PUT avec des paramètres body peut accepter
des champs non attendus qui altèrent l'état ou les autorisations.
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class IntegrityInference:
    """Inférence des propriétés d'intégrité (injection, mass assignment)."""

    def provider_id(self) -> str:
        return "builtin.integrity"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties: list[SecurityProperty] = []
        seen_statements: set[str] = set()

        # Règle 1 : paramètres user-controlled → surface d'injection
        for param in model.parameters:
            if not param.is_user_controlled:
                continue
            stmt = (
                f"input('{param.name}', location='{param.location}') is treated as data, "
                f"not as executable code or query fragment"
            )
            if stmt in seen_statements:
                continue
            seen_statements.add(stmt)
            properties.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement=stmt,
                model_nodes=[param.id],
                inference_confidence=0.6,
                source_observations=[],
            ))

        # Règle 2 : endpoints POST/PUT avec body params → mass assignment possible
        has_body_params = any(p for p in model.parameters if p.location == "body")
        if has_body_params:
            for ep in model.endpoints:
                if not ({"POST", "PUT"} & set(ep.methods)):
                    continue
                stmt = (
                    f"endpoint '{ep.path}' does not accept unexpected fields "
                    f"that alter authorization or state"
                )
                if stmt in seen_statements:
                    continue
                seen_statements.add(stmt)
                properties.append(SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.INTEGRITY,
                    formal_statement=stmt,
                    model_nodes=[ep.id],
                    inference_confidence=0.5,
                    source_observations=[],
                ))

        # Règle 3 : semantic-driven — exploite ParameterNode.semantic calculé par ApplicationModel
        # Chaque valeur sémantique correspond à une classe de vulnérabilité distincte.
        _SEMANTIC_TO_PROPERTY = {
            "file_path": (
                "input('{name}', location='{loc}') must reject ../ path traversal sequences",
                0.85,
            ),
            "url_redirect": (
                "input('{name}', location='{loc}') must validate URL to trusted domains only (SSRF/redirect)",
                0.80,
            ),
            "template_expr": (
                "input('{name}', location='{loc}') must not be evaluated as template expression (SSTI)",
                0.80,
            ),
            "xml_input": (
                "input('{name}', location='{loc}') XML parser must disable external entity processing (XXE)",
                0.85,
            ),
            "credential": (
                "input('{name}', location='{loc}') must not transmit credentials in cleartext",
                0.90,
            ),
        }

        seen_semantic: set[tuple[str, str, str]] = set()
        for param in model.parameters:
            if not param.semantic or param.semantic not in _SEMANTIC_TO_PROPERTY:
                continue
            key = (param.semantic, param.name, param.location)
            if key in seen_semantic:
                continue
            seen_semantic.add(key)

            stmt_template, confidence = _SEMANTIC_TO_PROPERTY[param.semantic]
            statement = stmt_template.format(name=param.name, loc=param.location)

            if statement in seen_statements:
                continue
            seen_statements.add(statement)

            # Boost confidence pour xml_input si l'endpoint accepte effectivement du XML
            if param.semantic == "xml_input":
                for ep in model.endpoints:
                    if param.id in ep.parameters and getattr(ep, "accepts_xml", False):
                        confidence = 0.95
                        break

            node_ids: list[str] = [param.id]
            for ep in model.endpoints:
                if param.id in ep.parameters:
                    node_ids.append(ep.id)

            properties.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement=statement,
                model_nodes=node_ids[:5],
                inference_confidence=confidence,
                source_observations=[],
            ))

        return properties
