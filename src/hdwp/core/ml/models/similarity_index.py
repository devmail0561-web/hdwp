# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SimilarityIndex — V4 Sprint 6.

k-NN cosine similarity sur EndpointEmbeddings (30D) pour transférer
les patterns de vulnérabilités entre sessions.

Problème résolu :
  Le VulnClassifier apprend en partant de zéro chaque session (min 20 samples).
  Le SimilarityIndex permet de réutiliser immédiatement les findings confirmés
  des sessions passées : "cet endpoint ressemble à X endpoints qui étaient
  vulnérables à bola → boost hypothesis bola".

Fonctionnement :
  - Index = liste de (EndpointEmbedding 30D, vuln_class, confidence) des
    findings confirmés, chargée depuis la table `finding_embeddings` au démarrage.
  - query(embedding) → k voisins les plus proches par cosine similarity.
  - property_type_boosts(embedding) → {PropertyType → max(similarity)} via
    le même mapping VULN_TO_PROPERTY_TYPE que le VulnClassifier.

Propriétés :
  - Pure Python, 0 dépendance externe.
  - O(30·N) par lookup : négligeable pour N < 10 000 entries.
  - Complément du VulnClassifier (pattern matching direct vs apprentissage statistique).
  - Active dès le premier finding confirmé (vs min 20 pour VulnClassifier).

ADR-ML-007 : SimilarityIndex utilise un seuil de similarité MIN_SIMILARITY=0.7
             pour ne boouster que les endpoints réellement comparables.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass

log = logging.getLogger(__name__)

MIN_SIMILARITY: float = 0.7   # seuil en dessous duquel un voisin est ignoré
DEFAULT_K: int = 3             # nombre de voisins par défaut

# Même mapping que VulnClassifier — maintenu ici pour éviter l'import circulaire
_VULN_TO_PROPERTY_TYPE: dict[str, str] = {
    "bola": "authorization",
    "authz": "authorization",
    "jwt": "authorization",
    "cors": "coherence",
    "sqli": "integrity",
    "xss": "integrity",
    "ssrf": "integrity",
    "path_traversal": "integrity",
    "http_smuggling": "state",
}


@dataclass
class SimilarEntry:
    embedding: list[float]
    vuln_class: str
    confidence: float = 1.0
    finding_id: str = ""


@dataclass
class SimilarMatch:
    vuln_class: str
    similarity: float
    confidence: float
    finding_id: str


class SimilarityIndex:
    """
    Index k-NN cosine pour le transfert de connaissances inter-sessions.

    Chargé au démarrage depuis la table `finding_embeddings` de la KB.
    Mis à jour en fin de session avec les nouveaux findings confirmés.
    """

    def __init__(self) -> None:
        self._entries: list[SimilarEntry] = []

    # ── Chargement ────────────────────────────────────────────────────────────

    def load(self, entries: list[dict]) -> None:
        """
        Charge les entries depuis les enregistrements KB.

        Chaque dict doit avoir :
          - embedding: list[float]  (30D)
          - vuln_class: str
          - confidence: float  (optionnel, défaut 1.0)
          - finding_id: str    (optionnel)
        """
        loaded = 0
        for e in entries:
            emb = e.get("embedding", [])
            if not emb:
                continue
            self._entries.append(SimilarEntry(
                embedding=emb,
                vuln_class=e.get("vuln_class", "unknown"),
                confidence=float(e.get("confidence", 1.0)),
                finding_id=e.get("finding_id", ""),
            ))
            loaded += 1
        if loaded:
            log.info("similarity_index.loaded entries=%d", loaded)

    def add(self, embedding: list[float], vuln_class: str,
            confidence: float = 1.0, finding_id: str = "") -> None:
        """Ajoute une entry à l'index (en-session, pour les findings courants)."""
        if embedding:
            self._entries.append(SimilarEntry(
                embedding=embedding, vuln_class=vuln_class,
                confidence=confidence, finding_id=finding_id,
            ))

    # ── Recherche ─────────────────────────────────────────────────────────────

    def query(self, embedding: list[float], k: int = DEFAULT_K) -> list[SimilarMatch]:
        """
        Retourne les k voisins les plus proches avec similarity >= MIN_SIMILARITY.

        Résultats triés par similarité décroissante.
        """
        if not self._entries or not embedding:
            return []

        scored: list[tuple[float, SimilarEntry]] = []
        for entry in self._entries:
            sim = _cosine(embedding, entry.embedding)
            if sim >= MIN_SIMILARITY:
                scored.append((sim, entry))

        scored.sort(key=lambda x: -x[0])
        return [
            SimilarMatch(
                vuln_class=e.vuln_class,
                similarity=round(sim, 4),
                confidence=e.confidence,
                finding_id=e.finding_id,
            )
            for sim, e in scored[:k]
        ]

    def vuln_boosts(self, embedding: list[float], k: int = DEFAULT_K) -> dict[str, float]:
        """
        Retourne un boost par vuln_class : max(similarity) sur les k voisins.

        Retourne un dict vide si aucun voisin ne dépasse MIN_SIMILARITY.
        """
        matches = self.query(embedding, k)
        boosts: dict[str, float] = {}
        for m in matches:
            boosts[m.vuln_class] = max(boosts.get(m.vuln_class, 0.0), m.similarity)
        return boosts

    def property_type_boosts(
        self, embedding: list[float], k: int = DEFAULT_K
    ) -> dict[str, float]:
        """
        Retourne un boost par PropertyType (valeur str).

        Agrège les vuln_class via _VULN_TO_PROPERTY_TYPE → max par groupe.
        Compatible avec HypothesisPrioritizer.set_ml_type_boosts().
        """
        vb = self.vuln_boosts(embedding, k)
        grouped: dict[str, float] = {}
        for vuln, boost in vb.items():
            pt = _VULN_TO_PROPERTY_TYPE.get(vuln, "integrity")
            grouped[pt] = max(grouped.get(pt, 0.0), boost)
        return grouped

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def n_entries(self) -> int:
        return len(self._entries)

    def stats(self) -> dict:
        from collections import Counter
        counts = Counter(e.vuln_class for e in self._entries)
        return {
            "n_entries": self.n_entries,
            "vuln_class_distribution": dict(counts),
        }


# ── Cosine similarity (pure Python) ──────────────────────────────────────────


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity entre deux vecteurs de même dimension."""
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    norm_a = math.sqrt(norm_a)
    norm_b = math.sqrt(norm_b)
    if norm_a < 1e-10 or norm_b < 1e-10:
        return 0.0
    return dot / (norm_a * norm_b)
