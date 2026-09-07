# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
HypothesisBandit : Thompson Sampling sur les bras (property_type, mutation_type).

Apprend en temps réel quels types d'hypothèses sont les plus fructueux sur la
cible en cours de scan. Mis à jour après chaque verdict oracle (CONFIRMED/REFUTED/
INSUFFICIENT_DATA).

Chaque bras est une distribution Beta(alpha, beta) :
  - alpha += reward (CONFIRMED → 1.0, AMBIGUOUS → 0.3, REFUTED → 0.0)
  - beta  += 1 - reward

score_arm() tire un échantillon Thompson → ordre probabiliste, exploratoire.

Les compteurs vivent en mémoire le temps du scan. La KnowledgeBase peut
initialiser les priors depuis l'historique inter-sessions (optionnel).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class ArmState:
    alpha: float = 1.0  # prior uniforme : Beta(1, 1) = uniforme sur [0,1]
    beta: float = 1.0
    pulls: int = 0

    def update(self, reward: float) -> None:
        """Mise à jour bayésienne : reward ∈ [0, 1]."""
        self.alpha += reward
        self.beta += 1.0 - reward
        self.pulls += 1

    def sample(self) -> float:
        """Tire un échantillon de la distribution Beta(alpha, beta)."""
        return random.betavariate(self.alpha, self.beta)


class HypothesisBandit:
    """
    Thompson Sampling multi-arm sur les clés (property_type, mutation_type).
    Réordonne les hypothèses PENDING pour favoriser les bras les plus prometteurs.
    """

    _REWARD_CONFIRMED = 1.0
    _REWARD_AMBIGUOUS = 0.3
    _REWARD_REFUTED = 0.0

    def __init__(self) -> None:
        self._arms: dict[tuple[str, str], ArmState] = {}

    def _arm(self, key: tuple[str, str]) -> ArmState:
        if key not in self._arms:
            self._arms[key] = ArmState()
        return self._arms[key]

    def _hypothesis_key(self, hyp: object) -> tuple[str, str]:
        """Extrait la clé d'arm depuis une Hypothesis."""
        property_type = getattr(hyp, "property_type", None) or "unknown"
        exps = getattr(hyp, "required_experiments", [])
        mutation_type = exps[0].mutation_type if exps else "unknown"
        return (property_type, mutation_type)

    def update(self, property_type: str, mutation_type: str, verdict: str, score: float = 0.0) -> None:
        """Met à jour le bras après un verdict oracle."""
        key = (property_type or "unknown", mutation_type or "unknown")
        reward = {
            "CONFIRMED": self._REWARD_CONFIRMED,
            "REFUTED": self._REWARD_REFUTED,
            "INSUFFICIENT_DATA": self._REWARD_AMBIGUOUS,
        }.get(verdict, score)
        self._arm(key).update(reward)

    def sort(self, hypotheses: list) -> list:
        """
        Retourne les hypothèses réordonnées par score Thompson Sampling.
        Les hypothèses HIGH restent favorisées : leur score est boosted.
        """
        if not hypotheses:
            return hypotheses

        _TIER_BOOST = {"HIGH": 0.3, "MEDIUM": 0.0, "LOW": -0.2}

        def _score(hyp: object) -> float:
            key = self._hypothesis_key(hyp)
            base = self._arm(key).sample()
            boost = _TIER_BOOST.get(getattr(hyp, "priority", "MEDIUM"), 0.0)
            return base + boost

        return sorted(hypotheses, key=_score, reverse=True)

    def stats(self) -> list[dict]:
        return [
            {
                "property_type": k[0],
                "mutation_type": k[1],
                "alpha": round(v.alpha, 3),
                "beta": round(v.beta, 3),
                "pulls": v.pulls,
                "estimated_rate": round(v.alpha / (v.alpha + v.beta), 3),
            }
            for k, v in sorted(self._arms.items(), key=lambda x: -x[1].alpha / (x[1].alpha + x[1].beta))
        ]
