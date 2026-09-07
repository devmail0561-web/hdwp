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

    def __init__(
        self,
        kb_stats: dict[tuple[str, str], dict[str, float]] | None = None,
        tuning: object = None,
    ) -> None:
        self._kb_stats = kb_stats or {}
        self._bola_role_boost = getattr(tuning, "bola_role_confirmation_boost", 0.15)

    def provider_id(self) -> str:
        return "builtin.authorization"

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
                base_confidence = 0.8 if len(model.roles) >= 2 else 0.5
                bola_stats = self._kb_stats.get(
                    ("authorization", "object_ref_change"), {}
                )
                if bola_stats.get("total", 0) >= 3:
                    historical_rate = bola_stats.get("confirmed_rate", 0.5)
                    confidence = 0.3 * base_confidence + 0.7 * historical_rate
                    confidence = max(0.3, min(0.95, confidence))
                else:
                    confidence = base_confidence

                # Boost comportemental : si deux rôles distincts ont observé status=200
                # sur les endpoints liés, la surface BOLA est confirmée par l'observation.
                for ep in related_endpoints:
                    auth_roles_200 = [
                        role for role, status in ep.status_by_role.items()
                        if role != "anonymous" and status == 200
                    ]
                    if len(auth_roles_200) >= 2:
                        confidence = min(0.95, confidence + self._bola_role_boost)
                        break

                # Endpoint comportementalement instable → surface plus prioritaire
                if any(
                    ep.behavioral_profile is not None
                    and ep.behavioral_profile.max_zscore_seen is not None
                    and ep.behavioral_profile.max_zscore_seen > 2.5
                    for ep in related_endpoints
                ):
                    confidence = min(0.95, confidence + 0.05)

                # Boost méthode destructive : DELETE/PUT/PATCH BOLA = destruction ou écrasement
                # d'un objet appartenant à un autre utilisateur → impact élevé
                _DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}
                if any(
                    bool(_DESTRUCTIVE & set(ep.methods))
                    for ep in related_endpoints
                ):
                    confidence = min(0.95, confidence + 0.10)

                # Endpoint exposant des champs de privilège (role, permissions...) → IDOR de données sensibles
                if any(getattr(ep, "contains_privilege_field", False) for ep in related_endpoints):
                    confidence = min(0.95, confidence + 0.08)
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
