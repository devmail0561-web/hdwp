# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires — EndpointClusterer (V4 Sprint 7)."""
from __future__ import annotations

import math
import random

import pytest

from hdwp.core.ml.models.endpoint_clusterer import (
    DEFAULT_K,
    MIN_SAMPLES,
    EndpointClusterer,
    _mean_vecs,
    _sq_dist,
)
from hdwp.core.ml.models.payload_optimizer import PayloadOptimizer


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_embedding(dim: int = 30, seed: int = 0) -> list[float]:
    rng = random.Random(seed)
    return [rng.uniform(-1.0, 1.0) for _ in range(dim)]


def _make_cluster_data(
    k: int = 3,
    points_per_cluster: int = 5,
    dim: int = 30,
    spread: float = 0.1,
) -> tuple[list[list[float]], list[str]]:
    """Génère k clusters bien séparés (centroïdes unitaires scalés)."""
    rng = random.Random(99)
    embeddings: list[list[float]] = []
    paths: list[str] = []
    for c in range(k):
        center = [rng.uniform(-2.0, 2.0) for _ in range(dim)]
        for j in range(points_per_cluster):
            point = [center[i] + rng.gauss(0, spread) for i in range(dim)]
            embeddings.append(point)
            paths.append(f"/api/cluster{c}/item{j}")
    return embeddings, paths


# ── Helpers géométriques ──────────────────────────────────────────────────────


def test_sq_dist_same_vector():
    v = [1.0, 2.0, 3.0]
    assert _sq_dist(v, v) == pytest.approx(0.0)


def test_sq_dist_orthogonal():
    assert _sq_dist([1.0, 0.0], [0.0, 1.0]) == pytest.approx(2.0)


def test_mean_vecs_single():
    result = _mean_vecs([[1.0, 2.0, 3.0]])
    assert result == pytest.approx([1.0, 2.0, 3.0])


def test_mean_vecs_two():
    result = _mean_vecs([[0.0, 0.0], [2.0, 4.0]])
    assert result == pytest.approx([1.0, 2.0])


def test_mean_vecs_empty():
    assert _mean_vecs([]) == []


# ── EndpointClusterer — construction ─────────────────────────────────────────


def test_default_k():
    c = EndpointClusterer()
    assert c.k == DEFAULT_K


def test_custom_k():
    c = EndpointClusterer(k=4)
    assert c.k == 4


def test_not_trained_initially():
    c = EndpointClusterer()
    assert not c.is_trained
    assert c.n_samples == 0


# ── fit ───────────────────────────────────────────────────────────────────────


def test_fit_below_min_samples_does_not_train():
    c = EndpointClusterer(k=8)
    embeddings = [_make_embedding(seed=i) for i in range(MIN_SAMPLES - 1)]
    c.fit(embeddings)
    assert not c.is_trained


def test_fit_below_k_does_not_train():
    c = EndpointClusterer(k=10)
    embeddings = [_make_embedding(seed=i) for i in range(8)]
    c.fit(embeddings)
    assert not c.is_trained


def test_fit_exactly_k_samples_trains():
    k = 4
    c = EndpointClusterer(k=k)
    embeddings = [_make_embedding(dim=30, seed=i) for i in range(k)]
    c.fit(embeddings)
    assert c.is_trained
    assert c.n_samples == k


def test_fit_produces_k_centroids():
    k = 4
    c = EndpointClusterer(k=k)
    embeddings = [_make_embedding(dim=30, seed=i) for i in range(20)]
    c.fit(embeddings)
    assert c.is_trained
    # Internal: verify via assign returns valid cluster IDs
    for emb in embeddings:
        cid = c.assign(emb)
        assert 0 <= cid < k


def test_fit_with_paths_builds_map():
    embeddings, paths = _make_cluster_data(k=3, points_per_cluster=4)
    c = EndpointClusterer(k=3)
    c.fit(embeddings, paths)
    assert c.is_trained
    pm = c.path_cluster_map
    assert len(pm) == len(paths)
    for path in paths:
        assert path in pm
        assert 0 <= pm[path] < 3


def test_fit_without_paths_empty_map():
    embeddings = [_make_embedding(seed=i) for i in range(16)]
    c = EndpointClusterer(k=4)
    c.fit(embeddings)
    assert c.is_trained
    assert c.path_cluster_map == {}


def test_fit_deterministic():
    """Même seed → mêmes centroïdes."""
    embeddings = [_make_embedding(dim=30, seed=i) for i in range(20)]
    c1 = EndpointClusterer(k=4)
    c2 = EndpointClusterer(k=4)
    c1.fit(embeddings)
    c2.fit(embeddings)
    for cid in range(4):
        for dim_i in range(30):
            assert c1._centroids[cid][dim_i] == pytest.approx(c2._centroids[cid][dim_i])


def test_fit_separated_clusters_assigns_consistently():
    """Clusters bien séparés : tous les points du cluster C mappent au même centroïde."""
    k = 3
    points_per_cluster = 6
    embeddings, paths = _make_cluster_data(k=k, points_per_cluster=points_per_cluster, spread=0.01)
    c = EndpointClusterer(k=k)
    c.fit(embeddings, paths)
    assert c.is_trained

    pm = c.path_cluster_map
    # Les points d'un même cluster doivent partager le même cluster ID
    for cluster_idx in range(k):
        cluster_paths = [f"/api/cluster{cluster_idx}/item{j}" for j in range(points_per_cluster)]
        cluster_ids = {pm[p] for p in cluster_paths}
        assert len(cluster_ids) == 1, f"cluster {cluster_idx} split across {cluster_ids}"


# ── assign ────────────────────────────────────────────────────────────────────


def test_assign_untrained_returns_zero():
    c = EndpointClusterer()
    emb = _make_embedding()
    assert c.assign(emb) == 0


def test_assign_trained_valid_range():
    c = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c.fit(embeddings)
    for emb in embeddings:
        cid = c.assign(emb)
        assert 0 <= cid < 4


def test_assign_same_embedding_consistent():
    c = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c.fit(embeddings)
    emb = _make_embedding(seed=99)
    assert c.assign(emb) == c.assign(emb)


def test_assign_paths():
    embeddings, paths = _make_cluster_data(k=3, points_per_cluster=4)
    c = EndpointClusterer(k=3)
    c.fit(embeddings)
    mapping = c.assign_paths(embeddings, paths)
    assert len(mapping) == len(paths)
    for path in paths:
        assert 0 <= mapping[path] < 3


# ── inertia ───────────────────────────────────────────────────────────────────


def test_inertia_untrained_is_inf():
    c = EndpointClusterer()
    assert c.inertia([_make_embedding()]) == float("inf")


def test_inertia_separated_clusters_low():
    """Clusters bien séparés → inertie plus basse que données aléatoires."""
    k = 3
    sep_embs, _ = _make_cluster_data(k=k, points_per_cluster=8, spread=0.05)
    rand_embs = [_make_embedding(seed=i) for i in range(k * 8)]

    c_sep = EndpointClusterer(k=k)
    c_sep.fit(sep_embs)
    inertia_sep = c_sep.inertia(sep_embs)

    c_rand = EndpointClusterer(k=k)
    c_rand.fit(rand_embs)
    inertia_rand = c_rand.inertia(rand_embs)

    assert inertia_sep < inertia_rand


# ── Persistence ───────────────────────────────────────────────────────────────


def test_to_serializable_structure():
    c = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c.fit(embeddings)
    data = c.to_serializable()
    assert "k" in data
    assert "n_samples" in data
    assert "centroids" in data
    assert "trained_at" in data
    assert data["k"] == 4
    assert data["n_samples"] == 20
    assert len(data["centroids"]) == 4


def test_to_serializable_centroids_are_lists():
    c = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c.fit(embeddings)
    data = c.to_serializable()
    for centroid in data["centroids"]:
        assert isinstance(centroid, list)
        assert all(isinstance(x, float) for x in centroid)


def test_load_serializable_trains():
    c1 = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c1.fit(embeddings)
    data = c1.to_serializable()

    c2 = EndpointClusterer()
    assert not c2.is_trained
    c2.load_serializable(data)
    assert c2.is_trained
    assert c2.k == 4
    assert c2.n_samples == 20


def test_load_serializable_roundtrip_assignments():
    """Même assignments avant et après sérialisation."""
    c1 = EndpointClusterer(k=4)
    embeddings = [_make_embedding(seed=i) for i in range(20)]
    c1.fit(embeddings)
    data = c1.to_serializable()

    c2 = EndpointClusterer()
    c2.load_serializable(data)

    test_embs = [_make_embedding(seed=100 + i) for i in range(10)]
    for emb in test_embs:
        assert c1.assign(emb) == c2.assign(emb)


def test_load_serializable_empty_noop():
    c = EndpointClusterer()
    c.load_serializable({})
    assert not c.is_trained


def test_set_path_cluster_map():
    c = EndpointClusterer()
    mapping = {"/api/users": 0, "/api/orders": 1}
    c.set_path_cluster_map(mapping)
    assert c.path_cluster_map == mapping


# ── stats ─────────────────────────────────────────────────────────────────────


def test_stats_untrained():
    c = EndpointClusterer()
    s = c.stats()
    assert not s["trained"]
    assert s["n_samples"] == 0


def test_stats_trained():
    embeddings, paths = _make_cluster_data(k=3, points_per_cluster=4)
    c = EndpointClusterer(k=3)
    c.fit(embeddings, paths)
    s = c.stats()
    assert s["trained"]
    assert s["k"] == 3
    assert s["n_samples"] == 12
    assert s["n_paths_mapped"] == 12
    assert sum(s["cluster_sizes"].values()) == 12


# ── PayloadOptimizer — intégration cluster map ────────────────────────────────


def test_payload_optimizer_set_cluster_map():
    opt = PayloadOptimizer()
    opt.set_cluster_map({"/api/users": 0, "/api/orders": 2})
    assert opt._cluster_map == {"/api/users": 0, "/api/orders": 2}


def test_payload_optimizer_cluster_fp_known_path():
    opt = PayloadOptimizer()
    opt.set_cluster_map({"/api/users": 3})
    result = opt._cluster_fp("/api/users", "GET:1:0:json")
    assert result == "C3:GET:1:0:json"


def test_payload_optimizer_cluster_fp_unknown_path():
    opt = PayloadOptimizer()
    opt.set_cluster_map({"/api/other": 1})
    result = opt._cluster_fp("/api/users", "GET:1:0:json")
    assert result == "GET:1:0:json"  # fallback


def test_payload_optimizer_cluster_fp_no_map():
    opt = PayloadOptimizer()
    result = opt._cluster_fp("/api/users", "GET:0:0:none")
    assert result == "GET:0:0:none"


def test_payload_optimizer_update_with_cluster():
    """update() avec ep_path connu met à jour le bras cluster ET le bras heuristique."""
    opt = PayloadOptimizer()
    opt.set_cluster_map({"/api/users": 2})
    base_fp = "GET:0:0:none"
    cluster_fp = "C2:GET:0:0:none"
    opt.update(base_fp, "identity_swap", "CONFIRMED", ep_path="/api/users")
    assert (base_fp, "identity_swap") in opt._arms
    assert (cluster_fp, "identity_swap") in opt._arms
    assert opt._arms[(cluster_fp, "identity_swap")].alpha > 1.0  # rewarded


def test_payload_optimizer_update_without_path_no_cluster_arm():
    opt = PayloadOptimizer()
    opt.set_cluster_map({"/api/users": 2})
    base_fp = "GET:0:0:none"
    opt.update(base_fp, "identity_swap", "CONFIRMED")
    # Seul le bras heuristique est créé
    cluster_fp = "C2:GET:0:0:none"
    assert (cluster_fp, "identity_swap") not in opt._arms


def test_payload_optimizer_sort_hypotheses_uses_cluster_fp():
    """sort_hypotheses utilise le fingerprint enrichi si cluster map défini."""
    opt = PayloadOptimizer()
    # Prime le bras cluster avec suffisamment de succès pour être déterministe
    # (50 updates → Beta(51,1) : P(sample < uniform) < 0.02%)
    opt.set_cluster_map({"/api/users/1": 5})
    for _ in range(50):
        opt.update("C5:GET:0:1:json", "identity_swap", "CONFIRMED")

    class FakeHyp:
        def __init__(self, path: str):
            self.required_experiments = [type("E", (), {
                "mutation_type": "identity_swap",
                "mutation_params": {"endpoint_path": path},
            })()]

    class FakeEndpoint:
        def __init__(self, path: str):
            self.path = path
            self.methods = ["GET"]
            self.auth_required = False
            self.response_content_type = "application/json"

    class FakeSnapshot:
        endpoints = [FakeEndpoint("/api/users/1"), FakeEndpoint("/api/orders")]

    hyps = [FakeHyp("/api/orders"), FakeHyp("/api/users/1")]
    sorted_hyps = opt.sort_hypotheses(hyps, FakeSnapshot())
    # L'hypothèse sur /api/users/1 doit être priorisée (bras C5 bien entraîné)
    assert sorted_hyps[0].required_experiments[0].mutation_params["endpoint_path"] == "/api/users/1"
