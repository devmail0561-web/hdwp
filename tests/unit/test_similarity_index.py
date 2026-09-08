# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires pour SimilarityIndex — V4 Sprint 6."""
from __future__ import annotations

import math
import pytest

from hdwp.core.ml.models.similarity_index import (
    SimilarityIndex,
    SimilarEntry,
    SimilarMatch,
    MIN_SIMILARITY,
    _cosine,
)


# ── _cosine ───────────────────────────────────────────────────────────────────


class TestCosine:
    def test_identical_vectors(self):
        v = [1.0, 2.0, 3.0]
        assert _cosine(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)

    def test_opposite_vectors(self):
        assert _cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)

    def test_zero_vector_returns_zero(self):
        assert _cosine([0.0, 0.0], [1.0, 1.0]) == pytest.approx(0.0)

    def test_near_identical(self):
        a = [1.0, 2.0, 3.0]
        b = [1.01, 2.01, 3.01]
        assert _cosine(a, b) > 0.999

    def test_different_magnitude_same_direction(self):
        assert _cosine([1.0, 0.0], [100.0, 0.0]) == pytest.approx(1.0)

    def test_partial_similarity(self):
        sim = _cosine([1.0, 1.0, 0.0], [1.0, 0.0, 0.0])
        assert 0.5 < sim < 1.0

    def test_30d_vectors(self):
        a = [float(i) for i in range(30)]
        b = [float(i) * 0.9 for i in range(30)]
        assert _cosine(a, b) > 0.99


# ── SimilarityIndex.load ──────────────────────────────────────────────────────


class TestLoad:
    def test_empty_load(self):
        idx = SimilarityIndex()
        idx.load([])
        assert idx.n_entries == 0

    def test_loads_entries(self):
        idx = SimilarityIndex()
        idx.load([
            {"embedding": [1.0] * 30, "vuln_class": "bola", "confidence": 0.9, "finding_id": "F1"},
            {"embedding": [0.5] * 30, "vuln_class": "sqli", "confidence": 0.8, "finding_id": "F2"},
        ])
        assert idx.n_entries == 2

    def test_skips_empty_embedding(self):
        idx = SimilarityIndex()
        idx.load([
            {"embedding": [], "vuln_class": "bola", "confidence": 1.0},
            {"embedding": [1.0] * 30, "vuln_class": "sqli", "confidence": 0.9},
        ])
        assert idx.n_entries == 1

    def test_default_confidence(self):
        idx = SimilarityIndex()
        idx.load([{"embedding": [1.0] * 30, "vuln_class": "bola"}])
        assert idx._entries[0].confidence == pytest.approx(1.0)

    def test_add_single_entry(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "sqli", confidence=0.85, finding_id="F1")
        assert idx.n_entries == 1
        assert idx._entries[0].vuln_class == "sqli"

    def test_add_ignores_empty(self):
        idx = SimilarityIndex()
        idx.add([], "sqli")
        assert idx.n_entries == 0


# ── SimilarityIndex.query ─────────────────────────────────────────────────────


class TestQuery:
    def _make_index(self) -> SimilarityIndex:
        idx = SimilarityIndex()
        idx.load([
            {"embedding": [1.0, 0.0] + [0.0] * 28, "vuln_class": "bola", "confidence": 0.9},
            {"embedding": [0.9, 0.1] + [0.0] * 28, "vuln_class": "bola", "confidence": 0.85},
            {"embedding": [0.0, 1.0] + [0.0] * 28, "vuln_class": "sqli", "confidence": 0.8},
            {"embedding": [-1.0, 0.0] + [0.0] * 28, "vuln_class": "authz", "confidence": 0.7},
        ])
        return idx

    def test_returns_similar_above_threshold(self):
        idx = self._make_index()
        query = [1.0, 0.0] + [0.0] * 28
        matches = idx.query(query, k=3)
        assert len(matches) >= 1
        assert all(m.similarity >= MIN_SIMILARITY for m in matches)

    def test_excludes_below_threshold(self):
        idx = self._make_index()
        # [-1, 0] est opposé à [1, 0] → cosine = -1 → en-dessous du seuil
        query = [1.0, 0.0] + [0.0] * 28
        matches = idx.query(query, k=10)
        vuln_classes = [m.vuln_class for m in matches]
        assert "authz" not in vuln_classes

    def test_returns_correct_vuln_class(self):
        idx = self._make_index()
        query = [1.0, 0.0] + [0.0] * 28
        matches = idx.query(query, k=1)
        assert matches[0].vuln_class == "bola"

    def test_sorted_by_similarity_desc(self):
        idx = self._make_index()
        query = [1.0, 0.0] + [0.0] * 28
        matches = idx.query(query, k=3)
        sims = [m.similarity for m in matches]
        assert sims == sorted(sims, reverse=True)

    def test_k_limits_results(self):
        idx = self._make_index()
        query = [1.0, 0.0] + [0.0] * 28
        matches = idx.query(query, k=1)
        assert len(matches) <= 1

    def test_empty_index_returns_empty(self):
        idx = SimilarityIndex()
        matches = idx.query([1.0] * 30)
        assert matches == []

    def test_empty_query_returns_empty(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "bola")
        assert idx.query([]) == []

    def test_match_fields(self):
        idx = SimilarityIndex()
        idx.load([{"embedding": [1.0] * 30, "vuln_class": "jwt", "confidence": 0.92, "finding_id": "F42"}])
        matches = idx.query([1.0] * 30, k=1)
        assert len(matches) == 1
        m = matches[0]
        assert m.vuln_class == "jwt"
        assert m.similarity == pytest.approx(1.0)
        assert m.confidence == pytest.approx(0.92)
        assert m.finding_id == "F42"


# ── vuln_boosts ───────────────────────────────────────────────────────────────


class TestVulnBoosts:
    def test_returns_max_per_vuln_class(self):
        idx = SimilarityIndex()
        # Deux entries bola — le max devrait être retenu
        idx.load([
            {"embedding": [1.0, 0.0] + [0.0] * 28, "vuln_class": "bola", "confidence": 1.0},
            {"embedding": [0.95, 0.05] + [0.0] * 28, "vuln_class": "bola", "confidence": 1.0},
        ])
        query = [1.0, 0.0] + [0.0] * 28
        boosts = idx.vuln_boosts(query)
        assert "bola" in boosts
        assert boosts["bola"] == pytest.approx(1.0, abs=0.01)

    def test_empty_when_no_match(self):
        idx = SimilarityIndex()
        idx.add([0.0, 1.0] + [0.0] * 28, "sqli")
        # Query orthogonale — pas de similarité suffisante
        boosts = idx.vuln_boosts([1.0, 0.0] + [0.0] * 28)
        # Similarité = 0.0 < MIN_SIMILARITY → vide
        assert boosts == {}

    def test_different_vuln_classes(self):
        idx = SimilarityIndex()
        idx.load([
            {"embedding": [1.0, 0.0] + [0.0] * 28, "vuln_class": "bola"},
            {"embedding": [0.8, 0.0] + [0.0] * 28, "vuln_class": "sqli"},
        ])
        boosts = idx.vuln_boosts([1.0, 0.0] + [0.0] * 28, k=3)
        assert "bola" in boosts
        assert "sqli" in boosts


# ── property_type_boosts ──────────────────────────────────────────────────────


class TestPropertyTypeBoosts:
    def test_bola_maps_to_authorization(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "bola")
        boosts = idx.property_type_boosts([1.0] * 30, k=1)
        assert "authorization" in boosts

    def test_sqli_maps_to_integrity(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "sqli")
        boosts = idx.property_type_boosts([1.0] * 30, k=1)
        assert "integrity" in boosts

    def test_cors_maps_to_coherence(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "cors")
        boosts = idx.property_type_boosts([1.0] * 30, k=1)
        assert "coherence" in boosts

    def test_max_per_property_type(self):
        idx = SimilarityIndex()
        # bola et authz mapent tous les deux sur authorization
        idx.load([
            {"embedding": [1.0, 0.0] + [0.0] * 28, "vuln_class": "bola", "confidence": 1.0},
            {"embedding": [0.9, 0.0] + [0.0] * 28, "vuln_class": "authz", "confidence": 1.0},
        ])
        boosts = idx.property_type_boosts([1.0, 0.0] + [0.0] * 28, k=3)
        # authorization = max des deux
        assert "authorization" in boosts
        assert boosts["authorization"] >= 0.9

    def test_empty_index_empty_boosts(self):
        idx = SimilarityIndex()
        assert idx.property_type_boosts([1.0] * 30) == {}


# ── stats ─────────────────────────────────────────────────────────────────────


class TestStats:
    def test_empty_stats(self):
        idx = SimilarityIndex()
        s = idx.stats()
        assert s["n_entries"] == 0
        assert s["vuln_class_distribution"] == {}

    def test_stats_populated(self):
        idx = SimilarityIndex()
        idx.add([1.0] * 30, "bola")
        idx.add([0.5] * 30, "bola")
        idx.add([0.3] * 30, "sqli")
        s = idx.stats()
        assert s["n_entries"] == 3
        assert s["vuln_class_distribution"]["bola"] == 2
        assert s["vuln_class_distribution"]["sqli"] == 1
