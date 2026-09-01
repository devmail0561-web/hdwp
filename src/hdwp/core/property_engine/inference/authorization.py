# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class AuthorizationInference:
    """Infers authorization properties from the application model."""

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties: list[SecurityProperty] = []
        properties.extend(self._infer_bola(model))
        properties.extend(self._infer_endpoint_auth(model))
        properties.extend(self._infer_role_separation(model))
        return properties

    def _infer_bola(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []
        for param in model.parameters:
            if param.affects_object and param.type_inferred in ("integer", "uuid"):
                related_endpoints = [
                    ep
                    for ep in model.endpoints
                    if param.id in ep.parameters or param.name in ep.path
                ]
                confidence = 0.8 if len(model.roles) >= 2 else 0.5
                props.append(
                    SecurityProperty(
                        id=generate_id("PROP"),
                        type=PropertyType.AUTHORIZATION,
                        formal_statement=(
                            f"access(S, resource) via parameter '{param.name}' "
                            f"=> owner(resource) = S"
                        ),
                        model_nodes=[param.id] + [ep.id for ep in related_endpoints],
                        inference_confidence=confidence,
                        source_observations=[],
                    )
                )
        return props

    def _infer_endpoint_auth(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []
        for ep in model.endpoints:
            if ep.auth_required and len(ep.roles_observed) >= 1:
                props.append(
                    SecurityProperty(
                        id=generate_id("PROP"),
                        type=PropertyType.AUTHORIZATION,
                        formal_statement=(
                            f"access(S, '{ep.path}') => S.role in {sorted(ep.roles_observed)}"
                        ),
                        model_nodes=[ep.id],
                        inference_confidence=0.7,
                        source_observations=[],
                    )
                )
        return props

    def _infer_role_separation(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []
        if len(model.roles) < 2:
            return props
        for i, role_a in enumerate(model.roles):
            for role_b in model.roles[i + 1 :]:
                exclusive_a = set(role_a.observed_permissions) - set(
                    role_b.observed_permissions
                )
                exclusive_b = set(role_b.observed_permissions) - set(
                    role_a.observed_permissions
                )
                if exclusive_a:
                    props.append(
                        SecurityProperty(
                            id=generate_id("PROP"),
                            type=PropertyType.AUTHORIZATION,
                            formal_statement=(
                                f"role '{role_b.name}' cannot access endpoints "
                                f"exclusive to '{role_a.name}': {sorted(exclusive_a)}"
                            ),
                            model_nodes=[role_a.id, role_b.id],
                            inference_confidence=0.75,
                            source_observations=[],
                        )
                    )
                if exclusive_b:
                    props.append(
                        SecurityProperty(
                            id=generate_id("PROP"),
                            type=PropertyType.AUTHORIZATION,
                            formal_statement=(
                                f"role '{role_a.name}' cannot access endpoints "
                                f"exclusive to '{role_b.name}': {sorted(exclusive_b)}"
                            ),
                            model_nodes=[role_a.id, role_b.id],
                            inference_confidence=0.75,
                            source_observations=[],
                        )
                    )
        return props
