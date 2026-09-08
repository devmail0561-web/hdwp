# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import ClassVar

from hdwp.core.model.schemas import PropertyType

_DEFAULT_WEIGHTS: dict[PropertyType, float] = {
    PropertyType.AUTHORIZATION: 1.0,
    PropertyType.CONFIDENTIALITY: 0.9,
    PropertyType.INTEGRITY: 0.8,
    PropertyType.STATE: 0.7,
    PropertyType.COHERENCE: 0.6,
    PropertyType.TEMPORAL: 0.5,
    PropertyType.CONCURRENCY: 0.4,
}


class HypothesisPrioritizer:
    """Computes hypothesis priority = f(impact, surface, observation_quality)."""

    # Kept as ClassVar for reference; actual weights per-instance are in _impact_weights.
    IMPACT_WEIGHTS: ClassVar[dict[PropertyType, float]] = _DEFAULT_WEIGHTS

    def __init__(
        self,
        weights: dict[PropertyType, float] | None = None,
        high_threshold: float = 0.60,
        medium_threshold: float = 0.30,
    ) -> None:
        self._impact_weights: dict[PropertyType, float] = weights or _DEFAULT_WEIGHTS
        self._high_threshold = high_threshold
        self._medium_threshold = medium_threshold
        # V4 Sprint 3 : boost ML par PropertyType (valeur str → facteur multiplicatif)
        # Peuplé via set_ml_type_boosts() après prédictions VulnClassifier
        self._ml_type_boosts: dict[str, float] = {}

    def set_ml_type_boosts(self, boosts: dict[str, float]) -> None:
        """
        Définit les facteurs de boost ML par PropertyType.

        boosts: {property_type_value → max_proba} — ex: {"authorization": 0.8}
        Le score de priorité sera multiplié par (1.0 + proba) pour ce type.
        Appelé par HDWPEngine après les prédictions VulnClassifier post-observation.
        """
        self._ml_type_boosts = dict(boosts)

    def compute_priority(
        self,
        property_type: PropertyType,
        affected_node_count: int,
        total_endpoints: int,
        observation_count: int,
    ) -> tuple[str, str]:
        """Return (priority, rationale) based on impact, surface and observations."""
        impact = self._impact_weights.get(property_type, 0.3)
        surface = affected_node_count / max(total_endpoints, 1)
        obs_factor = min(1.0, observation_count / 5)

        # Floor raised to 0.25 so large APIs (many endpoints) can still reach HIGH priority
        base_score = impact * max(surface, 0.25) * max(obs_factor, 0.1)

        # V4 Sprint 3 : boost ML — augmente l'impact si VulnClassifier prédit ce type
        ml_proba = self._ml_type_boosts.get(property_type.value, 0.0)
        score = base_score * (1.0 + ml_proba)

        if score >= self._high_threshold:
            level = "HIGH"
        elif score >= self._medium_threshold:
            level = "MEDIUM"
        else:
            level = "LOW"

        ml_note = f", ml_boost={ml_proba:.2f}" if ml_proba > 0.0 else ""
        rationale = (
            f"score={score:.2f} "
            f"(impact={impact:.1f}, surface={surface:.2f}, obs_factor={obs_factor:.2f}{ml_note})"
        )
        return level, rationale

    @classmethod
    def with_weights(
        cls,
        weights: dict[str, float],
        high_threshold: float = 0.60,
        medium_threshold: float = 0.30,
    ) -> HypothesisPrioritizer:
        """Crée un prioritizer avec des poids adaptés par la KnowledgeBase."""
        adapted: dict[PropertyType, float] = {}
        for pt in PropertyType:
            adapted[pt] = weights.get(pt.value, _DEFAULT_WEIGHTS.get(pt, 0.5))
        return cls(weights=adapted, high_threshold=high_threshold, medium_threshold=medium_threshold)
