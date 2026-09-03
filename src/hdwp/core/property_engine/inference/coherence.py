# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CoherenceInference: inférence des propriétés de cohérence et de logique métier.

Trois types de propriétés :
1. Business invariants : paramètres price/amount/quantity → doivent être positifs
2. CORS : endpoints authentifiés doivent restreindre les origines cross-site
3. Security headers : endpoints retournant des données sensibles
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)

BUSINESS_CRITICAL_NAMES = frozenset({
    "price", "amount", "quantity", "count", "total", "balance",
    "discount", "rate", "fee", "cost", "value", "limit", "credit",
    "score", "weight", "tax", "surcharge", "debit", "sum", "budget",
})


class CoherenceInference:
    """Inférence des propriétés de cohérence et logique métier."""

    def provider_id(self) -> str:
        return "builtin.coherence"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []
        seen_names: set[str] = set()

        # Règle 1 : paramètres business-critiques → invariant valeur positive
        for param in model.parameters:
            name_lower = param.name.lower()
            if not any(kw in name_lower for kw in BUSINESS_CRITICAL_NAMES):
                continue
            if name_lower in seen_names:
                continue
            if param.type_inferred not in ("integer", "string", "number"):
                continue
            seen_names.add(name_lower)

            props.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.COHERENCE,
                    formal_statement=(
                        f"business invariant: parameter '{param.name}' "
                        f"must be positive and within a valid business range"
                    ),
                    model_nodes=[param.id],
                    inference_confidence=0.65,
                    source_observations=[],
                )
            )

        # Règle 2 : CORS — endpoints authentifiés doivent restreindre les origines
        if len(model.roles) >= 2:
            auth_ep_ids = [ep.id for ep in model.endpoints if ep.auth_required]
            if auth_ep_ids:
                props.append(
                    SecurityProperty(
                        id=generate_id("PROP"),
                        type=PropertyType.COHERENCE,
                        formal_statement=(
                            "CORS: authenticated endpoints must restrict cross-origin access"
                        ),
                        model_nodes=auth_ep_ids[:5],
                        inference_confidence=0.6,
                        source_observations=[],
                    )
                )

        # Règle 3 : headers sécurité — endpoints retournant des données sensibles
        sensitive_ep_ids = []
        for ep in model.endpoints:
            for param in model.parameters:
                if param.affects_object and (param.id in ep.parameters or param.name in ep.path):
                    if ep.id not in sensitive_ep_ids:
                        sensitive_ep_ids.append(ep.id)
                    break

        if sensitive_ep_ids:
            props.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.COHERENCE,
                    formal_statement=(
                        "Security headers must be present on endpoints returning sensitive data"
                    ),
                    model_nodes=sensitive_ep_ids[:3],
                    inference_confidence=0.5,
                    source_observations=[],
                )
            )

        return props
