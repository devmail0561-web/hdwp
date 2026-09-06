# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)

BUSINESS_CRITICAL_NAMES = frozenset({
    "price", "amount", "quantity", "total", "balance", "fee", "discount",
    "cost", "credit", "debit", "sum", "payment", "transfer", "withdraw",
    "deposit", "vote", "stock", "inventory", "coupon", "redeem",
})

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


class ConcurrencyInference:
    """Infers concurrency (TOCTOU) properties from write endpoints with business-critical params."""

    def provider_id(self) -> str:
        return "builtin.concurrency"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties: list[SecurityProperty] = []
        seen: set[frozenset] = set()

        business_params = {
            p.id: p for p in model.parameters
            if any(kw in p.name.lower() for kw in BUSINESS_CRITICAL_NAMES)
            and p.type_inferred in ("integer", "string")
        }

        if not business_params:
            return []

        for ep in model.endpoints:
            if not any(m in _WRITE_METHODS for m in ep.methods):
                continue
            matching = [pid for pid in ep.parameters if pid in business_params]
            if not matching:
                continue

            sig = frozenset(matching)
            if sig in seen:
                continue
            seen.add(sig)

            param_names = [business_params[pid].name for pid in matching]
            method = next(m for m in ep.methods if m in _WRITE_METHODS)
            properties.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.CONCURRENCY,
                formal_statement=(
                    f"Concurrent {method} requests to '{ep.path}' on "
                    f"parameter(s) {param_names} must be atomic (TOCTOU race condition risk)"
                ),
                model_nodes=[ep.id] + matching,
                inference_confidence=0.65,
                source_observations=[],
            ))

        return properties
