# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
FeedbackLoop — V4 Sprint 8.

Apprentissage en ligne (SGD logistique) des poids de ConfidenceModelV2.

Problème résolu :
  ConfidenceModelV2 utilise des poids logistiques fixes (V2_DEFAULT_WEIGHTS).
  Ces poids ont été fixés manuellement sans connaissance du target réel.
  FeedbackLoop observe les paires (features 10D, verdict CONFIRMED/REFUTED)
  via l'event ML_FEEDBACK et ajuste les poids par gradient stochastique.

Algorithme — SGD logistique online :
  Pour chaque (x, y) avec y=1 (CONFIRMED) ou y=0 (REFUTED) :
    z = bias + Σ w_i · x_i
    y_hat = σ(z)
    err = y_hat - y
    w_i -= lr · (err · x_i + λ · w_i)   # gradient + L2
    bias -= lr · err

  Résultat : dimensions fortement actives sur des CONFIRMED findings voient
  leur poids augmenter ; celles actives sur des REFUTED le voient diminuer.
  Les poids convergent vers un équilibre reflétant l'historique du target.

Propriétés :
  - Pure Python, 0 dépendances externes.
  - Persistance des poids dans la KB (table feedback_weights).
  - Chargé au démarrage, injecté dans ConfidenceModelV2 via update_weights().
  - SESSION_DECAY appliqué en début de session : sessions récentes pèsent plus.

ADR-ML-009 : lr=0.05, λ=0.001, weight_min=-6.0, weight_max=6.0, bias_init=-4.0.
  La régularisation L2 empêche l'explosion des poids sur des cibles homogènes.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.context.config_schema import TuningConfig

log = logging.getLogger(__name__)

# 10 dimensions de ConfidenceModelV2
V2_DIMENSIONS = [
    "oracle_strength",
    "reproducibility",
    "observation_quality",
    "behavioral_specificity",
    "experiment_coverage",
    "temporal_signal",
    "crossrole_signal",
    "invariant_violated",
    "waf_bypass_success",
    "causal_depth",
]

# Hyperparamètres — ADR-ML-009
LEARNING_RATE: float = 0.05
L2_LAMBDA: float = 0.001
WEIGHT_MIN: float = -6.0
WEIGHT_MAX: float = 6.0
SESSION_DECAY: float = 0.95

# Phase 0.1: Supprimer duplication DEFAULT_WEIGHTS
# Importer depuis confidence.py (single source of truth)
from hdwp.core.oracle.confidence import (  # noqa: E402
    V2_DEFAULT_WEIGHTS,
    V2_DEFAULT_BIAS,
    extract_v2_weights_from_tuning,
)

# Aliases courts utilisés par les tests — copies pour éviter la mutation du canonique
DEFAULT_WEIGHTS = dict(V2_DEFAULT_WEIGHTS)
DEFAULT_BIAS = V2_DEFAULT_BIAS


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


class FeedbackLoop:
    """
    Adaptateur online des poids de ConfidenceModelV2 par SGD logistique.

    Chargé une fois au démarrage depuis la KB, mis à jour à chaque verdict oracle,
    sauvegardé en fin de session.
    """

    def __init__(self, tuning: TuningConfig | None = None) -> None:
        # Phase 0.1: initialiser depuis TuningConfig ou V2_DEFAULT_WEIGHTS (single source)
        if tuning is not None:
            initial_weights, initial_bias = extract_v2_weights_from_tuning(tuning)
        else:
            initial_weights, initial_bias = dict(V2_DEFAULT_WEIGHTS), V2_DEFAULT_BIAS
        self._weights: dict[str, float] = initial_weights
        self._bias: float = initial_bias
        # Cible du decay : poids initiaux (TuningConfig ou defaults), pas les defaults hardcodés
        self._decay_target_weights: dict[str, float] = dict(initial_weights)
        self._decay_target_bias: float = initial_bias
        self._n_updates: int = 0

    # ── Online learning ───────────────────────────────────────────────────────

    def observe(self, features: dict[str, float], verdict: str) -> None:
        """
        Met à jour les poids via une étape SGD.

        features : dict 10D (V2_DIMENSIONS) avec des valeurs dans [0, 1].
        verdict  : "CONFIRMED" (y=1) ou "REFUTED" (y=0). Autres verdicts ignorés.
        """
        if verdict not in ("CONFIRMED", "REFUTED"):
            return

        y = 1.0 if verdict == "CONFIRMED" else 0.0
        z = self._bias
        for dim in V2_DIMENSIONS:
            z += self._weights[dim] * features.get(dim, 0.0)
        y_hat = _sigmoid(z)
        err = y_hat - y

        for dim in V2_DIMENSIONS:
            x_i = features.get(dim, 0.0)
            grad = err * x_i + L2_LAMBDA * self._weights[dim]
            new_w = self._weights[dim] - LEARNING_RATE * grad
            self._weights[dim] = max(WEIGHT_MIN, min(WEIGHT_MAX, new_w))

        self._bias -= LEARNING_RATE * err
        self._n_updates += 1

        log.debug(
            "feedback_loop.update verdict=%s err=%.4f n=%d",
            verdict, err, self._n_updates,
        )

    def apply_session_decay(self) -> None:
        """
        Applique un decay exponentiel en début de session.

        Les poids sont attirés vers leur valeur par défaut afin que les
        sessions récentes pèsent plus que les anciennes.
        """
        for dim in V2_DIMENSIONS:
            w = self._weights[dim]
            target = self._decay_target_weights[dim]
            # Décay vers les poids initiaux (TuningConfig ou defaults) — jamais les hardcoded defaults
            self._weights[dim] = round(w * SESSION_DECAY + target * (1.0 - SESSION_DECAY), 6)
        self._bias = round(
            self._bias * SESSION_DECAY + self._decay_target_bias * (1.0 - SESSION_DECAY), 6
        )
        if self._n_updates > 0:
            log.debug(
                "feedback_loop.session_decay applied n_prev=%d", self._n_updates
            )

    # ── Accesseurs ───────────────────────────────────────────────────────────

    def current_weights(self) -> dict[str, float]:
        """Retourne une copie des poids actuels."""
        return dict(self._weights)

    def current_bias(self) -> float:
        return self._bias

    @property
    def n_updates(self) -> int:
        return self._n_updates

    def predict(self, features: dict[str, float]) -> float:
        """Score σ(w·x + bias) avec les poids courants."""
        z = self._bias
        for dim in V2_DIMENSIONS:
            z += self._weights[dim] * features.get(dim, 0.0)
        return _sigmoid(z)

    # ── Persistence ──────────────────────────────────────────────────────────

    def to_serializable(self) -> dict:
        return {
            "weights": {k: round(v, 6) for k, v in self._weights.items()},
            "bias": round(self._bias, 6),
            "n_updates": self._n_updates,
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    def load_serializable(self, data: dict) -> None:
        weights = data.get("weights", {})
        for dim in V2_DIMENSIONS:
            if dim in weights:
                self._weights[dim] = float(weights[dim])
        bias = data.get("bias")
        if bias is not None:
            self._bias = float(bias)
        self._n_updates = int(data.get("n_updates", 0))
        log.info(
            "feedback_loop.loaded n_updates=%d",
            self._n_updates,
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def drift(self) -> dict[str, float]:
        """Écart absolu moyen des poids par rapport aux défauts."""
        return {
            dim: round(abs(self._weights[dim] - V2_DEFAULT_WEIGHTS[dim]), 4)
            for dim in V2_DIMENSIONS
        }

    def stats(self) -> dict:
        return {
            "n_updates": self._n_updates,
            "bias": round(self._bias, 4),
            "weights": {k: round(v, 4) for k, v in self._weights.items()},
            "drift": self.drift(),
        }
