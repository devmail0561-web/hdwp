# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
EndpointClusterer — V4 Sprint 7.

k-means clustering (Lloyd's, pure Python) sur EndpointEmbeddings (30D)
pour dériver N clusters sémantiques d'endpoints.

Problème résolu :
  Le PayloadOptimizer utilise un fingerprint heuristique à 72 valeurs
  (method × auth × path_params × content_type). Ce fingerprint est statique
  et ne capture pas la sémantique des endpoints (profil de réponse, structure
  des paramètres, complexité, etc.).
  Le EndpointClusterer dérive k=8 clusters à partir des embeddings 30D réels
  et enrichit le fingerprint PayloadOptimizer avec le cluster ID :
  "C{id}:{method}:{has_auth}:{has_path_params}:{ct_bucket}".

Comportement :
  - fit(embeddings, paths) : entraîne k-means sur les embeddings, construit
    le path→cluster_id map pour la session courante.
  - assign(embedding) : cluster ID du voisin le plus proche (Euclidean).
  - Persistance des centroids dans la KB (table endpoint_clusters) pour
    assigner les endpoints des sessions futures sans refit.
  - Si N < MIN_SAMPLES : pas entraîné, fingerprint non augmenté.

ADR-ML-008 : k=8, seed=42, max_iter=100, tol=1e-6.
  Seed fixe pour reproductibilité inter-sessions.
"""
from __future__ import annotations

import logging
import math
import random
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DEFAULT_K: int = 8
MIN_SAMPLES: int = 8   # == k par défaut, impossible de clustérer avec < k points
MAX_ITER: int = 100
CONVERGENCE_TOL: float = 1e-6


# ── Helpers géométriques (pure Python) ───────────────────────────────────────


def _sq_dist(a: list[float], b: list[float]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b))


def _mean_vecs(vecs: list[list[float]]) -> list[float]:
    if not vecs:
        return []
    d = len(vecs[0])
    n = len(vecs)
    return [sum(v[i] for v in vecs) / n for i in range(d)]


# ── EndpointClusterer ─────────────────────────────────────────────────────────


class EndpointClusterer:
    """
    k-means clustering sur EndpointEmbeddings (30D) pour fingerprints sémantiques.

    Enrichit le PayloadOptimizer avec un cluster ID stable par endpoint,
    permettant une généralisation plus rapide des stratégies de mutation.
    """

    def __init__(self, k: int = DEFAULT_K) -> None:
        self._k = k
        self._centroids: list[list[float]] = []
        self._trained = False
        self._n_samples = 0
        self._path_cluster_map: dict[str, int] = {}

    # ── Training ─────────────────────────────────────────────────────────────

    def fit(
        self,
        embeddings: list[list[float]],
        paths: list[str] | None = None,
    ) -> None:
        """
        Entraîne k-means (Lloyd's) sur les embeddings fournis.

        Si paths est fourni (même longueur que embeddings), construit le
        path→cluster_id map utilisé par PayloadOptimizer.
        """
        n = len(embeddings)
        if n < self._k:
            log.debug(
                "endpoint_clusterer.fit_skipped n=%d k=%d",
                n, self._k,
            )
            return

        rng = random.Random(42)
        centroids = [list(v) for v in rng.sample(embeddings, self._k)]
        assignments: list[int] = [0] * n

        for _iteration in range(MAX_ITER):
            # Assign step
            new_assignments = [
                min(range(self._k), key=lambda c, emb=emb: _sq_dist(emb, centroids[c]))  # type: ignore[misc]
                for emb in embeddings
            ]

            # Update step
            new_centroids: list[list[float]] = []
            moved = False
            for c in range(self._k):
                cluster_pts = [embeddings[i] for i, a in enumerate(new_assignments) if a == c]
                if not cluster_pts:
                    new_centroids.append(centroids[c])  # empty cluster: keep centroid
                    continue
                new_c = _mean_vecs(cluster_pts)
                if _sq_dist(new_c, centroids[c]) > CONVERGENCE_TOL:
                    moved = True
                new_centroids.append(new_c)

            assignments = new_assignments
            centroids = new_centroids
            if not moved:
                log.debug("endpoint_clusterer.converged iteration=%d", _iteration)
                break

        self._centroids = centroids
        self._trained = True
        self._n_samples = n

        if paths is not None:
            self._path_cluster_map = {
                paths[i]: assignments[i]
                for i in range(min(len(paths), len(assignments)))
            }
            log.info(
                "endpoint_clusterer.fit k=%d n=%d paths=%d",
                self._k, n, len(self._path_cluster_map),
            )
        else:
            log.info("endpoint_clusterer.fit k=%d n=%d", self._k, n)

    def assign(self, embedding: list[float]) -> int:
        """Retourne le cluster ID (0 à k-1) du centroïde le plus proche."""
        if not self._trained or not self._centroids:
            return 0
        return min(range(self._k), key=lambda c: _sq_dist(embedding, self._centroids[c]))

    def assign_paths(
        self,
        embeddings: list[list[float]],
        paths: list[str],
    ) -> dict[str, int]:
        """Assigne un cluster à chaque (path, embedding) sans refitter."""
        return {
            paths[i]: self.assign(embeddings[i])
            for i in range(min(len(paths), len(embeddings)))
        }

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def is_trained(self) -> bool:
        return self._trained

    @property
    def k(self) -> int:
        return self._k

    @property
    def n_samples(self) -> int:
        return self._n_samples

    @property
    def path_cluster_map(self) -> dict[str, int]:
        return dict(self._path_cluster_map)

    def set_path_cluster_map(self, mapping: dict[str, int]) -> None:
        """Injecte un path→cluster_id map (utilisé par assign_paths post-load)."""
        self._path_cluster_map = dict(mapping)

    # ── Persistence ──────────────────────────────────────────────────────────

    def to_serializable(self) -> dict:
        """Sérialise les centroïdes pour la KB."""
        return {
            "k": self._k,
            "n_samples": self._n_samples,
            "centroids": [list(c) for c in self._centroids],
            "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    def load_serializable(self, data: dict) -> None:
        """Restaure les centroïdes depuis la KB (sans path_cluster_map)."""
        centroids = data.get("centroids", [])
        if not centroids:
            return
        self._k = int(data.get("k", self._k))
        self._n_samples = int(data.get("n_samples", 0))
        self._centroids = [list(c) for c in centroids]
        self._trained = True
        log.info(
            "endpoint_clusterer.loaded k=%d n_samples=%d",
            self._k, self._n_samples,
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        from collections import Counter
        counts = Counter(self._path_cluster_map.values())
        return {
            "k": self._k,
            "n_samples": self._n_samples,
            "trained": self._trained,
            "n_paths_mapped": len(self._path_cluster_map),
            "cluster_sizes": dict(sorted(counts.items())),
        }

    def inertia(self, embeddings: list[list[float]]) -> float:
        """Inertie (somme des distances² aux centroïdes) — indicateur qualité."""
        if not self._trained:
            return float("inf")
        total = 0.0
        for emb in embeddings:
            c = self.assign(emb)
            total += _sq_dist(emb, self._centroids[c])
        return total
