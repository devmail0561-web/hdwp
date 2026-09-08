# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ActiveLearner — V4 Sprint 5.

Uncertainty sampling pour l'exploration de l'espace hypothèses.

Problème résolu :
  Le PayloadOptimizer (Thompson Sampling) apprend quel arm est le plus *efficace*
  (exploitation). Il ne sait pas quels arms n'ont pas encore été suffisamment testés
  (exploration). L'ActiveLearner comble ce manque.

Deux sources d'incertitude combinées :
  1. Entropie VulnClassifier par endpoint :
       H(ep) = mean(-p*log2(p) - (1-p)*log2(1-p)) sur les 9 types de vuln.
       H haute → on ne sait pas quel vuln type prédomine → vaut la peine d'explorer.

  2. Couverture PayloadOptimizer par bras (fingerprint, mutation_type) :
       Bras peu tirés → incertitude sur l'efficacité → exploration utile.

Score combiné par hypothèse :
  combined = (1 - w) * thompson_score  +  w * entropy_score
  où w = exploration_weight(total_pulls) = 1 / (1 + 0.1 * total_pulls)
       → 1.0 en début de session (exploration pure)
       → décroît vers 0.05 au fur et à mesure que le PayloadOptimizer accumule de l'expérience

ADR-ML-005 : l'ActiveLearner *biaise* le tri, pas la décision oracle.
ADR-ML-006 : w décroît avec √pulls pour amortir rapidement l'exploration initiale.
"""
from __future__ import annotations

import logging
import math

log = logging.getLogger(__name__)

_MIN_EXPLORATION_WEIGHT: float = 0.05
_EXPLORATION_DECAY: float = 0.1   # w = 1 / (1 + decay * pulls)
_PRIOR_ENTROPY: float = 0.5       # prior pour endpoints sans prédictions VulnClassifier


class ActiveLearner:
    """
    Uncertainty sampling : combine l'exploitation Thompson (PayloadOptimizer)
    et l'exploration entropique (VulnClassifier + couverture bras).

    Cycle de vie :
      1. Post-VulnClassifier predictions : update_endpoint_entropy() pour chaque endpoint
      2. Avant sort_hypotheses() : appel via engine.py à la place de PayloadOptimizer seul
      3. sort_hypotheses() délègue au PayloadOptimizer pour le Thompson score
         et combine avec l'entropie endpoint
    """

    def __init__(self) -> None:
        self._endpoint_entropy: dict[str, float] = {}   # path → entropie [0, 1]

    # ── Entropy ───────────────────────────────────────────────────────────────

    @staticmethod
    def compute_entropy(vuln_probs: dict[str, float]) -> float:
        """
        Entropie binaire moyenne sur les probabilités de vuln types.

        Chaque type est une Bernoulli(p) indépendante.
        H(p) = -p·log₂(p) - (1-p)·log₂(1-p), normalisée ∈ [0, 1].

        Exemples :
          all p=0.5  → H=1.0 (incertitude maximale)
          all p→0   → H→0.0 (endpoint probablement sain)
          mixed      → H ∈ ]0, 1[
        """
        if not vuln_probs:
            return _PRIOR_ENTROPY
        total = 0.0
        for p in vuln_probs.values():
            p = max(1e-9, min(1 - 1e-9, p))
            total -= p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p)
        return total / len(vuln_probs)

    def update_endpoint_entropy(self, endpoint_path: str, vuln_probs: dict[str, float]) -> None:
        """Enregistre l'entropie des prédictions VulnClassifier pour un endpoint."""
        self._endpoint_entropy[endpoint_path] = self.compute_entropy(vuln_probs)

    def endpoint_entropy(self, endpoint_path: str) -> float:
        """Retourne l'entropie pour un endpoint, prior si inconnu."""
        return self._endpoint_entropy.get(endpoint_path, _PRIOR_ENTROPY)

    # ── Exploration weight ────────────────────────────────────────────────────

    @staticmethod
    def exploration_weight(total_pulls: int) -> float:
        """
        w = 1 / (1 + decay * pulls), clampé à [_MIN_EXPLORATION_WEIGHT, 1.0].

        Démarre à 1.0 (exploration pure), décroît rapidement dès les premières pulls.
        À 100 pulls → w ≈ 0.09, à 200 pulls → w ≈ 0.05 (quasi-exploitation pure).
        """
        return max(_MIN_EXPLORATION_WEIGHT, 1.0 / (1.0 + _EXPLORATION_DECAY * total_pulls))

    # ── Combined scoring ──────────────────────────────────────────────────────

    def combined_score(
        self,
        thompson_score: float,
        endpoint_path: str,
        total_pulls: int,
    ) -> float:
        """
        Score combiné exploitation–exploration.

        thompson_score : tirage Beta(α, β) du PayloadOptimizer (ou prior 0.5)
        endpoint_path  : chemin d'endpoint pour récupérer l'entropie
        total_pulls    : pulls totaux du PayloadOptimizer (détermine le poids d'exploration)
        """
        w = self.exploration_weight(total_pulls)
        entropy = self.endpoint_entropy(endpoint_path)
        return (1.0 - w) * thompson_score + w * entropy

    # ── Hypothesis sorting ────────────────────────────────────────────────────

    def sort_hypotheses(
        self,
        hypotheses: list,
        model_snapshot: object,
        optimizer: object | None = None,
    ) -> list:
        """
        Trie les hypothèses en combinant :
          - Thompson Sampling du PayloadOptimizer (exploitation)
          - Entropie VulnClassifier de l'endpoint (exploration)

        Si optimizer est None, trie uniquement par entropie.
        Si aucune entropie n'est connue, délègue entièrement à l'optimizer.
        """
        if not hypotheses:
            return hypotheses

        # Si aucune entropie disponible et pas d'optimizer → ordre inchangé
        if not self._endpoint_entropy and optimizer is None:
            return hypotheses

        ep_index: dict[str, object] = {}
        if model_snapshot is not None:
            for ep in (getattr(model_snapshot, "endpoints", None) or []):
                ep_index[getattr(ep, "path", "")] = ep

        total_pulls = optimizer.total_pulls if optimizer is not None else 0

        def _score(hyp: object) -> float:
            ep_path = _extract_hyp_endpoint(hyp)
            mutation = _hyp_mutation(hyp)

            # Thompson score depuis optimizer (ou prior uniforme)
            if optimizer is not None:
                ep = ep_index.get(ep_path)
                fp = (
                    optimizer.fingerprint_from_endpoint(ep)
                    if ep is not None
                    else "UNKNOWN:0:0:none"
                )
                thompson = optimizer._arm(fp, mutation).sample()
            else:
                thompson = 0.5

            return self.combined_score(thompson, ep_path, total_pulls)

        result = sorted(hypotheses, key=_score, reverse=True)
        log.debug(
            "active_learner.sorted n=%d pulls=%d w=%.2f known_entropies=%d",
            len(result), total_pulls,
            self.exploration_weight(total_pulls),
            len(self._endpoint_entropy),
        )
        return result

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Retourne les métriques de l'ActiveLearner."""
        entropies = list(self._endpoint_entropy.values())
        return {
            "n_endpoints_with_entropy": len(entropies),
            "mean_entropy": round(sum(entropies) / len(entropies), 3) if entropies else 0.0,
            "max_entropy": round(max(entropies), 3) if entropies else 0.0,
            "min_entropy": round(min(entropies), 3) if entropies else 0.0,
            "high_uncertainty_endpoints": [
                path for path, h in self._endpoint_entropy.items() if h > 0.7
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────────────────


def _extract_hyp_endpoint(hyp: object) -> str:
    """Extrait le chemin d'endpoint d'une Hypothesis."""
    for exp in (getattr(hyp, "required_experiments", None) or []):
        params: dict = getattr(exp, "mutation_params", {}) or {}
        ep = (
            params.get("endpoint_path", "")
            or params.get("target_endpoint", "")
            or params.get("authenticated_endpoint", "")
        )
        if ep:
            return ep
    return ""


def _hyp_mutation(hyp: object) -> str:
    """Extrait le mutation_type d'une Hypothesis."""
    exps = getattr(hyp, "required_experiments", None) or []
    return getattr(exps[0], "mutation_type", "unknown") if exps else "unknown"
