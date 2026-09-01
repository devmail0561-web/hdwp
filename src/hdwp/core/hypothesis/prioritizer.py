# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import ClassVar

from hdwp.core.model.schemas import PropertyType


class HypothesisPrioritizer:

    """Computes hypothesis priority = f(impact, surface, observation_quality)."""

    IMPACT_WEIGHTS: ClassVar[dict[PropertyType, float]] = {
        PropertyType.AUTHORIZATION: 1.0,
        PropertyType.CONFIDENTIALITY: 0.9,
        PropertyType.INTEGRITY: 0.8,
        PropertyType.STATE: 0.7,
        PropertyType.COHERENCE: 0.6,
        PropertyType.TEMPORAL: 0.5,
        PropertyType.CONCURRENCY: 0.4,
    }

    def compute_priority(
        self,
        property_type: PropertyType,
        affected_node_count: int,
        total_endpoints: int,
        observation_count: int,
    ) -> tuple[str, str]:
        """Return (priority, rationale) based on impact, surface and observations."""
        impact = self.IMPACT_WEIGHTS.get(property_type, 0.3)
        surface = affected_node_count / max(total_endpoints, 1)
        obs_factor = min(1.0, observation_count / 5)

        score = impact * max(surface, 0.1) * max(obs_factor, 0.1)

        if score >= 0.6:
            level = "HIGH"
        elif score >= 0.3:
            level = "MEDIUM"
        else:
            level = "LOW"

        rationale = (
            f"score={score:.2f} "
            f"(impact={impact:.1f}, surface={surface:.2f}, obs_factor={obs_factor:.2f})"
        )
        return level, rationale

    @classmethod
    def with_weights(cls, weights: dict[str, float]) -> HypothesisPrioritizer:
        """
        Crée un prioritizer avec des poids adaptés par la KnowledgeBase.
        Les clés de weights sont des valeurs de PropertyType (strings).
        """
        instance = cls.__new__(cls)
        adapted: dict[PropertyType, float] = {}
        for pt in PropertyType:
            adapted[pt] = weights.get(pt.value, cls.IMPACT_WEIGHTS.get(pt, 0.5))
        instance.IMPACT_WEIGHTS = adapted  # type: ignore[misc]
        return instance
