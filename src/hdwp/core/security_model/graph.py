# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SecurityModelGraph : modèle sémantique de sécurité de l'application cible.

Contrairement à ApplicationModelData (structurel), ce graphe capture :
  - Les invariants de propriété des ressources (qui peut accéder à quoi)
  - Les flux d'identité (quel endpoint produit des tokens, avec quels claims)
  - Les règles d'autorisation dérivées des observations cross-rôles

Construit depuis ApplicationModelData.response_corpus et les champs comportementaux
des EndpointNode (status_by_role, contains_privilege_field, etc.).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData

_OWNER_FIELDS = frozenset({
    "user_id", "owner_id", "account_id", "created_by", "sub", "member_id",
    "author_id", "creator_id", "assigned_to", "belongs_to",
})

_ADMIN_PATH_RE = re.compile(
    r'/(?:admin|manage|management|internal|staff|superuser|root|system|backoffice)',
    re.IGNORECASE
)


@dataclass
class ResourceOwnership:
    """Un endpoint expose une ressource dont l'accès est contrôlé par l'identité du demandeur."""
    endpoint: str                           # "/api/orders/{id}"
    id_param: str                           # paramètre qui identifie la ressource
    owner_field: str                        # champ dans le body qui varie par rôle
    roles_with_access: list[str]            # rôles qui reçoivent 2xx
    roles_denied: list[str]                 # rôles qui reçoivent 4xx
    observed_owner_values: dict[str, Any]   # {role_name: owner_field_value}
    confidence: float = 0.7


@dataclass
class AuthorizationInvariant:
    """Un endpoint a une restriction d'accès basée sur une propriété de l'identité."""
    endpoint_pattern: str
    required_property: str  # "ownership" | "role:admin" | "auth_required"
    confidence: float = 0.6
    evidence: list[str] = field(default_factory=list)


@dataclass
class IdentityFlow:
    """Un endpoint produit des tokens/JWTs avec des claims exploitables."""
    source_endpoint: str
    token_field: str        # nom du champ JSON qui contient le JWT
    decoded_claims: dict    # claims décodés (sub, role, exp, etc.)


@dataclass
class SecurityModelGraph:
    resource_ownerships: list[ResourceOwnership] = field(default_factory=list)
    authorization_invariants: list[AuthorizationInvariant] = field(default_factory=list)
    identity_flows: list[IdentityFlow] = field(default_factory=list)

    @classmethod
    def build(cls, model: ApplicationModelData) -> SecurityModelGraph:
        """Construit le graphe de sécurité depuis un snapshot ApplicationModelData."""
        graph = cls()

        for ep in model.endpoints:
            path = ep.path

            # ── Flux d'identité : endpoint qui retourne un JWT ─────────────
            if ep.jwt_field_names:
                response_bodies = model.response_corpus.get(path, {})
                for role_bodies in response_bodies.values():
                    if not role_bodies:
                        continue
                    for field_name in ep.jwt_field_names:
                        token_val = role_bodies[0].get(field_name)
                        if token_val and isinstance(token_val, str):
                            claims = _decode_jwt_claims(token_val)
                            if claims:
                                graph.identity_flows.append(IdentityFlow(
                                    source_endpoint=path,
                                    token_field=field_name,
                                    decoded_claims=claims,
                                ))
                            break
                    break

            # ── Ownership invariant : cross-role response diffing ──────────
            corpus_for_ep = model.response_corpus.get(path, {})
            if len(corpus_for_ep) >= 2:
                owner_field = _detect_owner_field(corpus_for_ep)
                if owner_field:
                    roles_200 = [
                        role for role, status in ep.status_by_role.items()
                        if 200 <= status < 300
                    ]
                    roles_4xx = [
                        role for role, status in ep.status_by_role.items()
                        if status in (401, 403, 404)
                    ]
                    # Extraire les valeurs observées du champ propriétaire par rôle
                    observed_values = {}
                    for role, bodies in corpus_for_ep.items():
                        if bodies:
                            v = bodies[0].get(owner_field)
                            if v is not None:
                                observed_values[role] = v

                    # Trouver le paramètre ID le plus probable
                    id_param = _find_id_param(ep.path, model)

                    confidence = 0.70
                    if roles_4xx:
                        confidence += 0.15  # accès refusé observé = enforcement probable
                    if owner_field.lower() in _OWNER_FIELDS:
                        confidence += 0.08  # nom sémantique reconnu
                    confidence = min(0.95, confidence)

                    graph.resource_ownerships.append(ResourceOwnership(
                        endpoint=path,
                        id_param=id_param or "id",
                        owner_field=owner_field,
                        roles_with_access=roles_200,
                        roles_denied=roles_4xx,
                        observed_owner_values=observed_values,
                        confidence=confidence,
                    ))

            # ── Règles d'autorisation : endpoints admin ───────────────────
            if ep.auth_required and _ADMIN_PATH_RE.search(path):
                evidence = [f"path_pattern:{path}", "auth_required:true"]
                if ep.status_by_role:
                    evidence.extend(f"{r}→{s}" for r, s in ep.status_by_role.items())
                graph.authorization_invariants.append(AuthorizationInvariant(
                    endpoint_pattern=path,
                    required_property="role:admin",
                    confidence=0.75,
                    evidence=evidence,
                ))

            # ── Endpoints avec champs privilège exposés ───────────────────
            if ep.contains_privilege_field and ep.auth_required:
                graph.authorization_invariants.append(AuthorizationInvariant(
                    endpoint_pattern=path,
                    required_property="ownership",
                    confidence=0.70,
                    evidence=[f"contains_privilege_field:{ep.contains_privilege_field}"],
                ))

        return graph


def _detect_owner_field(response_corpus: dict[str, list[dict]]) -> str | None:
    """Retourne le champ qui varie entre rôles — indicateur de propriété."""
    if len(response_corpus) < 2:
        return None
    roles_with_bodies = {r: b for r, b in response_corpus.items() if b}
    if len(roles_with_bodies) < 2:
        return None

    first_bodies = [bodies[0] for bodies in roles_with_bodies.values()]
    common_keys = set(first_bodies[0].keys())
    for body in first_bodies[1:]:
        common_keys &= set(body.keys())

    varying_keys = []
    for k in common_keys:
        values = [str(body.get(k)) for body in first_bodies]
        if len(set(values)) > 1:
            varying_keys.append(k)

    # Priorité aux noms sémantiquement owner-like
    for k in varying_keys:
        if k.lower() in _OWNER_FIELDS:
            return k
    # Fallback : premier champ variant qui est numérique
    for k in varying_keys:
        sample = first_bodies[0].get(k)
        if isinstance(sample, int):
            return k
    return varying_keys[0] if varying_keys else None


def _find_id_param(path: str, model: ApplicationModelData) -> str | None:
    """Trouve le nom du paramètre ID dans le path ou les paramètres de l'endpoint."""
    # Chercher un paramètre de path du type {name_id} ou {id}
    m = re.search(r'\{([a-z_]+)\}', path, re.IGNORECASE)
    if m:
        return m.group(1)
    # Chercher dans les paramètres de l'endpoint
    for ep in model.endpoints:
        if ep.path == path:
            for pid in ep.parameters:
                for p in model.parameters:
                    if p.id == pid and p.affects_object:
                        return p.name
    return None


def _decode_jwt_claims(token: str) -> dict:
    """Décode les claims d'un JWT sans vérification de signature."""
    try:
        from hdwp.core.experiment.jwt_mutator import decode_jwt_insecure
        decoded = decode_jwt_insecure(token)
        if decoded:
            _, payload, _ = decoded
            return payload or {}
    except Exception:
        pass
    return {}
