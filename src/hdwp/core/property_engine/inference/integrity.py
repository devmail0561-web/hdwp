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

        return properties
