# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
InvariantDeriver : dérive des SecurityProperty depuis le SecurityModelGraph.

Contrairement aux plugins (qui appliquent des templates), cet module génère
des hypothèses avec les valeurs réelles observées — les vrais IDs, les vrais
rôles, les vrais claims JWT de CETTE application.

C'est la différence entre :
  [template]  "tester param id avec valeur 0, -1, 999999"
  [invariant] "user_a a vu order_id=15 avec user_id=42 ; tester avec user_b (user_id=43)"
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData

from hdwp.core.model.schemas import (
    ExperimentSpec,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
    generate_id,
)
from hdwp.core.security_model.graph import SecurityModelGraph

# Rang de privilège inféré depuis les noms de rôles — heuristique simple
_PRIVILEGE_RANK = {
    "admin": 100, "superuser": 100, "root": 100, "administrator": 100,
    "manager": 80, "moderator": 70, "staff": 60, "supervisor": 60,
    "premium": 40, "pro": 40,
    "user": 20, "member": 20, "viewer": 10, "anonymous": 0, "guest": 5,
}


class InvariantDeriver:
    """Module d'inférence qui dérive des propriétés depuis le SecurityModelGraph."""

    def provider_id(self) -> str:
        return "builtin.invariant_deriver"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Point d'entrée standard pour InferenceRegistry."""
        if not model.response_corpus:
            return []

        graph = SecurityModelGraph.build(model)
        properties: list[SecurityProperty] = []

        properties.extend(self._derive_ownership_properties(graph, model))
        properties.extend(self._derive_jwt_escalation_properties(graph, model))
        properties.extend(self._derive_admin_access_properties(graph, model))

        return properties

    def _derive_ownership_properties(
        self, graph: SecurityModelGraph, model: ApplicationModelData
    ) -> list[SecurityProperty]:
        """BOLA avec les vraies valeurs observées dans le corpus."""
        props: list[SecurityProperty] = []
        for ownership in graph.resource_ownerships:
            if ownership.confidence < 0.65:
                continue

            # Générer des ExperimentSpec ciblés avec les vraies valeurs cross-rôle
            experiments = self._build_bola_experiments(ownership, model)
            if not experiments:
                continue

            prop = SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.AUTHORIZATION,
                formal_statement=(
                    f"ResourceOwnership invariant: '{ownership.endpoint}' — "
                    f"field '{ownership.owner_field}' doit correspondre à l'identité du demandeur"
                ),
                model_nodes=_find_endpoint_ids(ownership.endpoint, model),
                inference_confidence=ownership.confidence,
                source_observations=[],
            )
            # Attacher les expériences directement à la propriété via les hypothèses
            # (la propriété sera consommée par HypothesisEngine._on_property_inferred)
            prop._derived_hypotheses = experiments  # type: ignore[attr-defined]
            props.append(prop)

        return props

    def _build_bola_experiments(
        self, ownership: Any, model: ApplicationModelData
    ) -> list[ExperimentSpec]:
        """Construit des ExperimentSpec BOLA avec les IDs réels du corpus."""
        specs = []
        # Trouver des valeurs d'IDs réelles depuis les deux rôles
        role_values = ownership.observed_owner_values
        if len(role_values) < 2:
            return []

        roles = list(role_values.keys())
        role_a, role_b = roles[0], roles[1]
        val_a = role_values.get(role_a)
        val_b = role_values.get(role_b)

        if val_a is None or val_b is None or str(val_a) == str(val_b):
            return []

        specs.append(ExperimentSpec(
            mutation_type="object_ref_change",
            base_request=NormalizedRequest(method="GET", url=""),
            mutation_params={
                "parameter_name": ownership.id_param,
                "parameter_location": "path",
                "endpoint_path": ownership.endpoint,
                "cross_role_probe": True,
                "_derived_from": "invariant_deriver",
                "_roles_tested": f"{role_a}→{role_b}",
            },
            description=(
                f"Invariant BOLA: {ownership.endpoint} — "
                f"{role_a} (owner_id={val_a}) accède à la ressource de {role_b} (owner_id={val_b})"
            ),
        ))
        return specs

    def _derive_jwt_escalation_properties(
        self, graph: SecurityModelGraph, model: ApplicationModelData
    ) -> list[SecurityProperty]:
        """JWT claim escalation avec les vraies valeurs de rôles observées."""
        props: list[SecurityProperty] = []
        if not graph.identity_flows:
            return props

        # Collecter tous les rôles observés dans les réponses
        all_observed_roles: list[str] = []
        for ep in model.endpoints:
            for role_val in ep.observed_roles:
                if role_val not in all_observed_roles:
                    all_observed_roles.append(role_val)

        for flow in graph.identity_flows:
            claims = flow.decoded_claims
            current_role = claims.get("role") or claims.get("scope")
            if current_role is None:
                continue

            # Trouver un rôle plus élevé dans les valeurs observées
            elevated = _find_elevated_role(str(current_role), all_observed_roles)
            if elevated is None:
                continue

            props.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.AUTHORIZATION,
                formal_statement=(
                    f"JWT claim escalation: '{flow.source_endpoint}' retourne un token "
                    f"avec claim 'role={current_role}' — escalader vers '{elevated}'"
                ),
                model_nodes=[],
                inference_confidence=0.82,
                source_observations=[],
            ))
            # Stocker les claims ciblés pour usage par HypothesisEngine
            props[-1]._elevated_claims = {"role": elevated}  # type: ignore[attr-defined]
            props[-1]._jwt_source_endpoint = flow.source_endpoint  # type: ignore[attr-defined]

        return props

    def _derive_admin_access_properties(
        self, graph: SecurityModelGraph, model: ApplicationModelData
    ) -> list[SecurityProperty]:
        """Endpoints admin avec des rôles non-admin qui devraient être testés."""
        props: list[SecurityProperty] = []
        for invariant in graph.authorization_invariants:
            if invariant.required_property != "role:admin":
                continue

            # Trouver les rôles non-admin qui ont des permissions sur d'autres endpoints
            non_admin_roles = [
                r.name for r in model.roles
                if r.name not in ("admin", "superuser", "root", "administrator")
                and r.observed_permissions
            ]
            if not non_admin_roles:
                continue

            props.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.AUTHORIZATION,
                formal_statement=(
                    f"Admin access invariant: '{invariant.endpoint_pattern}' "
                    f"ne devrait être accessible qu'aux administrateurs"
                ),
                model_nodes=_find_endpoint_ids(invariant.endpoint_pattern, model),
                inference_confidence=invariant.confidence,
                source_observations=[],
            ))
            props[-1]._test_roles = non_admin_roles  # type: ignore[attr-defined]
            props[-1]._admin_endpoint = invariant.endpoint_pattern  # type: ignore[attr-defined]

        return props


def _find_elevated_role(current_role: str, observed_roles: list[str]) -> str | None:
    """Trouve un rôle plus privilégié que current_role dans la liste observée."""
    current_rank = _PRIVILEGE_RANK.get(current_role.lower(), 20)
    best_role = None
    best_rank = current_rank
    for role in observed_roles:
        rank = _PRIVILEGE_RANK.get(role.lower(), 20)
        if rank > best_rank:
            best_rank = rank
            best_role = role
    return best_role


def _find_endpoint_ids(endpoint_pattern: str, model: ApplicationModelData) -> list[str]:
    """Retourne les IDs des EndpointNode qui matchent le pattern."""
    return [ep.id for ep in model.endpoints if ep.path == endpoint_pattern]
