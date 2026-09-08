# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CrossSessionTransfer — V4 Sprint 9.

Transfert des poids FeedbackLoop entre sessions sur des targets similaires.

Problème résolu :
  FeedbackLoop démarre avec les poids par défaut (V2_DEFAULT_WEIGHTS) sur chaque
  nouveau target. Si on a déjà des poids convergés sur un target similaire
  (même type d'API, même architecture), ces poids offrent un meilleur point de
  départ que les défauts — réduisant le temps de convergence.

Algorithme — interpolation linéaire pondérée :
  Pour un transfer_factor f ∈ [0, 1] :
    w_blended_i = w_source_i · f + w_default_i · (1 - f)
    bias_blended = bias_source · f + bias_default · (1 - f)

  transfer_factor selon la similarité :
    - exact     (même target_hash) → f = 1.0  — copie directe
    - same_type (même target_type) → f = 0.7  — transfert fort
    - cross_type (type différent)  → f = 0.3  — transfert faible

  Résultat : les poids "chauffent" depuis une base pertinente plutôt
  que de partir des défauts manuels.

Propriétés :
  - Pure Python, 0 dépendances externes.
  - Indépendant de FeedbackLoop — consomme et produit des dict sérialisables.
  - Appliqué une seule fois au démarrage, avant apply_session_decay().
  - N'écrit rien dans la KB — lecture seule, l'engine s'en charge.

ADR-ML-010 : transfer_factors = {exact: 1.0, same_type: 0.7, cross_type: 0.3}.
  Les seuils reflètent la dégradation de pertinence inter-contexts.
  cross_type à 0.3 (et non 0.0) car les patterns de base (reproducibility,
  oracle_strength) sont corrélés au-delà du type d'application.
"""
from __future__ import annotations

import logging

from hdwp.core.ml.models.feedback_loop import DEFAULT_BIAS, DEFAULT_WEIGHTS, V2_DIMENSIONS

log = logging.getLogger(__name__)

# Facteurs de transfert — ADR-ML-010
TRANSFER_EXACT: float = 1.0
TRANSFER_SAME_TYPE: float = 0.7
TRANSFER_CROSS_TYPE: float = 0.3

# Nombre minimum de mises à jour dans la source pour accepter le transfert.
# En dessous de ce seuil, les poids source sont trop bruités pour être utiles.
MIN_UPDATES_FOR_TRANSFER: int = 5


def _transfer_factor(source_target_type: str, dest_target_type: str,
                     source_target_hash: str, dest_target_hash: str) -> float:
    """Retourne le transfer_factor selon la similarité des targets."""
    if source_target_hash and dest_target_hash and source_target_hash == dest_target_hash:
        return TRANSFER_EXACT
    if source_target_type and dest_target_type and source_target_type == dest_target_type:
        return TRANSFER_SAME_TYPE
    return TRANSFER_CROSS_TYPE


class CrossSessionTransfer:
    """
    Calcule les poids FeedbackLoop initiaux d'une session par transfert depuis
    les poids d'une session précédente sur un target similaire.

    Usage dans engine.py :
        transfer = CrossSessionTransfer()
        result = transfer.select_and_blend(
            snapshots=await kb.list_feedback_weights_snapshots(),
            dest_target_hash=target_hash,
            dest_target_type=url_target_type,
        )
        if result:
            feedback_loop.load_serializable(result)
    """

    def select_and_blend(
        self,
        snapshots: list[dict],
        dest_target_hash: str,
        dest_target_type: str,
    ) -> dict | None:
        """
        Sélectionne la meilleure source parmi les snapshots et retourne un dict
        sérialisable compatible avec FeedbackLoop.load_serializable().

        snapshots : liste de dicts avec keys :
            target_hash, target_type, weights, bias, n_updates

        Retourne None si aucune source n'est suffisamment fiable
        (n_updates < MIN_UPDATES_FOR_TRANSFER).
        """
        if not snapshots:
            return None

        # Filtrer les sources avec assez d'updates
        eligible = [
            s for s in snapshots
            if int(s.get("n_updates", 0)) >= MIN_UPDATES_FOR_TRANSFER
        ]
        if not eligible:
            log.debug(
                "cross_session_transfer.no_eligible_source min_updates=%d",
                MIN_UPDATES_FOR_TRANSFER,
            )
            return None

        # Choisir la source avec le transfer_factor le plus élevé,
        # à égalité on préfère celle avec le plus de mises à jour (plus fiable).
        def _score(s: dict) -> tuple[float, int]:
            f = _transfer_factor(
                source_target_type=s.get("target_type", ""),
                dest_target_type=dest_target_type,
                source_target_hash=s.get("target_hash", ""),
                dest_target_hash=dest_target_hash,
            )
            return (f, int(s.get("n_updates", 0)))

        best = max(eligible, key=_score)
        factor = _score(best)[0]

        if factor < TRANSFER_CROSS_TYPE:
            # Normalement impossible avec la logique _transfer_factor
            return None

        blended_weights, blended_bias = self._blend(
            source_weights=best.get("weights", {}),
            source_bias=float(best.get("bias", DEFAULT_BIAS)),
            transfer_factor=factor,
        )

        log.info(
            "cross_session_transfer.applied factor=%.1f source_hash=%s "
            "source_type=%s dest_type=%s n_updates_source=%d",
            factor,
            best.get("target_hash", "?"),
            best.get("target_type", "?"),
            dest_target_type,
            best.get("n_updates", 0),
        )

        return {
            "weights": blended_weights,
            "bias": blended_bias,
            # n_updates=0 : la session actuelle part de 0 (poids hérités, pas les updates source)
            "n_updates": 0,
        }

    def _blend(
        self,
        source_weights: dict[str, float],
        source_bias: float,
        transfer_factor: float,
    ) -> tuple[dict[str, float], float]:
        """
        Interpole source → défauts selon transfer_factor.

        transfer_factor = 1.0 → copie exacte
        transfer_factor = 0.0 → poids par défaut (jamais appliqué en pratique)
        """
        f = max(0.0, min(1.0, transfer_factor))
        blended: dict[str, float] = {}
        for dim in V2_DIMENSIONS:
            w_src = float(source_weights.get(dim, DEFAULT_WEIGHTS[dim]))
            w_def = DEFAULT_WEIGHTS[dim]
            blended[dim] = round(w_src * f + w_def * (1.0 - f), 6)
        blended_bias = round(source_bias * f + DEFAULT_BIAS * (1.0 - f), 6)
        return blended, blended_bias

    def blend(
        self,
        source_weights: dict[str, float],
        source_bias: float,
        transfer_factor: float,
    ) -> tuple[dict[str, float], float]:
        """API publique pour tests et usage direct."""
        return self._blend(source_weights, source_bias, transfer_factor)
