# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
TemporalInference: inférence des propriétés temporelles.

Règles :
1. Tout endpoint avec authentification Bearer doit invalider les tokens expirés
2. Les sessions doivent avoir une durée de vie limitée

Prérequis : les endpoints doivent être marqués auth_required=True
(auto-détectés par ApplicationModel._update_auth_required).
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class TemporalInference:
    """Infers temporal properties from the application model."""

    def provider_id(self) -> str:
        return "builtin.temporal"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []

        auth_endpoints = [ep for ep in model.endpoints if ep.auth_required]
        bearer_roles = [r for r in model.roles if r.name != "anonymous"]

        if not auth_endpoints or not bearer_roles:
            return props

        path_list = [ep.path for ep in auth_endpoints[:3]]
        props.append(SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.TEMPORAL,
            formal_statement=(
                f"expired(token) => ∀ protected_action in {path_list}, denied(action)"
            ),
            model_nodes=[ep.id for ep in auth_endpoints[:3]],
            inference_confidence=0.65,
            source_observations=[],
        ))

        return props
