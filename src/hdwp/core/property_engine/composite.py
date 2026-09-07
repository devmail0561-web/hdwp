# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CompositeInference : passe post-modules qui croise les SecurityProperty produites
par les modules individuels pour détecter des conjonctions à haute valeur.

Chaque règle reçoit :
  - `properties`  : liste de SecurityProperty déjà inférées ce cycle
  - `model`       : ApplicationModelData courant

Et retourne de nouvelles SecurityProperty composites (ou une liste vide).
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class CompositeInference:
    """Règles de conjonction inter-modules."""

    def provider_id(self) -> str:
        return "builtin.composite"

    def infer_composite(
        self,
        properties: list[SecurityProperty],
        model: ApplicationModelData,
    ) -> list[SecurityProperty]:
        result: list[SecurityProperty] = []
        result.extend(_rule_bola_data_leak(properties, model))
        result.extend(_rule_injection_sensitive_endpoint(properties, model))
        result.extend(_rule_bola_plus_race(properties, model))
        return result


# ── Règle 1 : BOLA candidate + objet privé/sensible → IDOR data leak ─────────

def _rule_bola_data_leak(
    properties: list[SecurityProperty],
    model: ApplicationModelData,
) -> list[SecurityProperty]:
    """
    Si un paramètre est BOLA candidate (authorization) ET que l'endpoint retourne
    un objet de sensibilité 'private' ou 'sensitive' (confidentiality), la fuite
    de données est directe — confidence élevée.
    """
    result: list[SecurityProperty] = []

    bola_props = [
        p for p in properties
        if p.type == PropertyType.AUTHORIZATION
        and "parameter" in p.formal_statement
        and p.inference_confidence >= 0.5
    ]
    confidential_props = [
        p for p in properties
        if p.type == PropertyType.CONFIDENTIALITY
        and p.inference_confidence >= 0.4
    ]

    if not bola_props or not confidential_props:
        return result

    # Chercher les endpoints qui apparaissent dans les deux ensembles de model_nodes
    bola_nodes: set[str] = {n for p in bola_props for n in p.model_nodes}
    conf_nodes: set[str] = {n for p in confidential_props for n in p.model_nodes}
    overlap = bola_nodes & conf_nodes

    if not overlap:
        # Tentative via le nom du paramètre → objet → sensibilité
        for bola_p in bola_props:
            for ep in model.endpoints:
                if ep.id not in bola_nodes:
                    continue
                for obj in model.objects:
                    if obj.owner_parameter and obj.sensitivity in ("private", "sensitive"):
                        if any(p.id == obj.owner_parameter for p in model.parameters):
                            overlap.add(ep.id)

    for node_id in overlap:
        confidence = min(0.93, max(
            p.inference_confidence for p in bola_props if node_id in p.model_nodes
        ) + 0.10)
        result.append(SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.AUTHORIZATION,
            formal_statement=(
                f"BOLA + private data: accessing object via node '{node_id}' "
                f"leaks sensitive/private data — IDOR data disclosure"
            ),
            model_nodes=[node_id],
            inference_confidence=confidence,
            source_observations=[],
        ))

    return result


# ── Règle 2 : Injection + endpoint sensible → injection critique ──────────────

def _rule_injection_sensitive_endpoint(
    properties: list[SecurityProperty],
    model: ApplicationModelData,
) -> list[SecurityProperty]:
    """
    Si un endpoint présente une surface d'injection (integrity PROP avec sqli/ssti)
    ET une propriété de confidentialité ou cohérence sensible sur le même endpoint,
    la combinaison est critique.
    """
    result: list[SecurityProperty] = []

    injection_props = [
        p for p in properties
        if p.type == PropertyType.INTEGRITY
        and any(kw in p.formal_statement.lower() for kw in ("sqli", "injection", "template", "xxe"))
        and p.inference_confidence >= 0.5
    ]
    sensitive_props = [
        p for p in properties
        if p.type in (PropertyType.CONFIDENTIALITY, PropertyType.COHERENCE)
        and p.inference_confidence >= 0.4
    ]

    if not injection_props or not sensitive_props:
        return result

    inj_nodes: set[str] = {n for p in injection_props for n in p.model_nodes}
    sens_nodes: set[str] = {n for p in sensitive_props for n in p.model_nodes}
    overlap = inj_nodes & sens_nodes

    for node_id in overlap:
        confidence = min(0.92, max(
            p.inference_confidence for p in injection_props if node_id in p.model_nodes
        ) + 0.12)
        result.append(SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement=(
                f"Critical injection: node '{node_id}' has both injection surface "
                f"and sensitive data access — high-impact exploitation path"
            ),
            model_nodes=[node_id],
            inference_confidence=confidence,
            source_observations=[],
        ))

    return result


# ── Règle 3 : BOLA + concurrence → IDOR race condition ───────────────────────

def _rule_bola_plus_race(
    properties: list[SecurityProperty],
    model: ApplicationModelData,
) -> list[SecurityProperty]:
    """
    BOLA candidate + TOCTOU/concurrence sur le même endpoint → surface d'attaque compound.
    """
    result: list[SecurityProperty] = []

    bola_props = [
        p for p in properties
        if p.type == PropertyType.AUTHORIZATION
        and "parameter" in p.formal_statement
        and p.inference_confidence >= 0.5
    ]
    concurrency_props = [
        p for p in properties
        if p.type == PropertyType.CONCURRENCY
        and p.inference_confidence >= 0.4
    ]

    if not bola_props or not concurrency_props:
        return result

    bola_nodes: set[str] = {n for p in bola_props for n in p.model_nodes}
    conc_nodes: set[str] = {n for p in concurrency_props for n in p.model_nodes}
    overlap = bola_nodes & conc_nodes

    for node_id in overlap:
        confidence = min(0.88, max(
            p.inference_confidence for p in bola_props if node_id in p.model_nodes
        ) + 0.08)
        result.append(SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.AUTHORIZATION,
            formal_statement=(
                f"Compound BOLA+race: node '{node_id}' is both BOLA-vulnerable "
                f"and has concurrent write access — race-condition IDOR"
            ),
            model_nodes=[node_id],
            inference_confidence=confidence,
            source_observations=[],
        ))

    return result
