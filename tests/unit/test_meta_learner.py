# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires — MetaLearner (V4 Sprint 10)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.ml.meta_learner import MetaLearner


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_kb(tmp_path: Path):
    from hdwp.core.knowledge.base import KnowledgeBase
    return KnowledgeBase(db_path=tmp_path / "test.db")


def _make_snapshot(n_endpoints: int = 3):
    """Crée un ApplicationModelData minimal."""
    from hdwp.core.model.schemas import ApplicationModelData, EndpointNode
    endpoints = []
    for i in range(n_endpoints):
        ep = EndpointNode(
            path=f"/api/resource/{i}",
            method="GET",
            parameters=[],
        )
        endpoints.append(ep)
    return ApplicationModelData(endpoints=endpoints, roles=[], parameters=[])


# ── MetaLearner.load — composants optionnels ──────────────────────────────────

@pytest.mark.asyncio
async def test_load_returns_meta_learner_instance(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert isinstance(ml, MetaLearner)
    await kb.close()


@pytest.mark.asyncio
async def test_load_feedback_loop_always_present(tmp_path: Path):
    """FeedbackLoop est toujours instancié (pas de min threshold)."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.feedback_loop is not None
    await kb.close()


@pytest.mark.asyncio
async def test_load_payload_optimizer_always_present(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.payload_optimizer is not None
    await kb.close()


@pytest.mark.asyncio
async def test_load_active_learner_always_present(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.active_learner is not None
    await kb.close()


@pytest.mark.asyncio
async def test_load_oracle_model_none_when_not_trained(tmp_path: Path):
    """OracleModel absent si aucun modèle sauvegardé sur disque."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    # En CI, aucun modèle oracle entraîné → None attendu
    assert ml.oracle_model is None
    await kb.close()


@pytest.mark.asyncio
async def test_load_vuln_classifier_none_when_not_trained(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.vuln_classifier is None
    await kb.close()


@pytest.mark.asyncio
async def test_load_similarity_index_none_when_no_embeddings(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    # Aucun finding_embedding en KB → None
    assert ml.similarity_index is None
    await kb.close()


@pytest.mark.asyncio
async def test_load_similarity_index_loaded_when_embeddings_present(tmp_path: Path):
    from hdwp.core.ml.models.feedback_loop import V2_DIMENSIONS
    kb = _make_kb(tmp_path)
    await kb.store_finding_embedding(
        finding_id="F-001",
        embedding=[0.1] * 30,
        vuln_class="bola",
        session_id="S-001",
        confidence=0.9,
    )
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.similarity_index is not None
    assert ml.similarity_index.n_entries == 1
    await kb.close()


@pytest.mark.asyncio
async def test_load_feedback_loop_loads_from_kb(tmp_path: Path):
    """Si des poids sont en KB, feedback_loop les charge."""
    from hdwp.core.ml.models.feedback_loop import DEFAULT_WEIGHTS
    kb = _make_kb(tmp_path)
    custom_weights = dict(DEFAULT_WEIGHTS)
    custom_weights["oracle_strength"] = 3.0
    await kb.store_feedback_weights({
        "weights": custom_weights,
        "bias": -2.0,
        "n_updates": 15,
    })
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    assert ml.feedback_loop is not None
    # Après apply_session_decay, le poids oracle_strength doit rester > DEFAULT (3.0 > 1.8)
    w = ml.feedback_loop.current_weights()
    assert w["oracle_strength"] > DEFAULT_WEIGHTS["oracle_strength"]
    await kb.close()


@pytest.mark.asyncio
async def test_load_uses_cross_session_transfer_when_no_current_weights(tmp_path: Path):
    """Sans poids 'current', CrossSessionTransfer est utilisé si des snapshots existent."""
    from hdwp.core.ml.models.feedback_loop import DEFAULT_WEIGHTS
    kb = _make_kb(tmp_path)
    custom_weights = dict(DEFAULT_WEIGHTS)
    custom_weights["oracle_strength"] = 3.0
    # Stocker des poids pour un autre target (même type)
    await kb.store_feedback_weights_for_target(
        target_hash="other_hash",
        target_type="api",
        data={"weights": custom_weights, "bias": -2.0, "n_updates": 20},
    )
    ml = await MetaLearner.load(kb, target_hash="new_hash", target_type="api")
    assert ml.feedback_loop is not None
    # same_type transfer factor=0.7 → poids oracle_strength > default
    w = ml.feedback_loop.current_weights()
    assert w["oracle_strength"] > DEFAULT_WEIGHTS["oracle_strength"]
    await kb.close()


# ── MetaLearner.inject_feedback_into_oracle ───────────────────────────────────

@pytest.mark.asyncio
async def test_inject_feedback_calls_oracle_update(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")

    oracle_mock = MagicMock()
    oracle_mock.update_v2_weights = MagicMock()
    # Forcer fb_weights_to_inject non-None
    ml._fb_weights_to_inject = {"weights": {}, "bias": -4.0, "n_updates": 0}
    ml.inject_feedback_into_oracle(oracle_mock)
    oracle_mock.update_v2_weights.assert_called_once()
    await kb.close()


@pytest.mark.asyncio
async def test_inject_feedback_noop_when_no_weights_to_inject(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    ml._fb_weights_to_inject = None

    oracle_mock = MagicMock()
    oracle_mock.update_v2_weights = MagicMock()
    ml.inject_feedback_into_oracle(oracle_mock)
    oracle_mock.update_v2_weights.assert_not_called()
    await kb.close()


# ── MetaLearner.sort_hypotheses ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sort_hypotheses_empty_list(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    result = ml.sort_hypotheses([], _make_snapshot())
    assert result == []
    await kb.close()


@pytest.mark.asyncio
async def test_sort_hypotheses_returns_list(tmp_path: Path):
    """sort_hypotheses retourne une liste même si ActiveLearner/Optimizer sont None."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    # Neutraliser les composants pour tester le fallback
    ml._active_learner = None
    ml._payload_optimizer = None
    fake_hypotheses = [MagicMock(), MagicMock()]
    result = ml.sort_hypotheses(fake_hypotheses, _make_snapshot())
    assert result == fake_hypotheses
    await kb.close()


# ── MetaLearner.stats ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_returns_dict(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    s = ml.stats()
    assert isinstance(s, dict)
    for key in ("oracle_model", "vuln_classifier", "payload_optimizer",
                "active_learner", "similarity_index", "endpoint_clusterer", "feedback_loop"):
        assert key in s
    await kb.close()


@pytest.mark.asyncio
async def test_stats_feedback_loop_shows_n_updates(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    s = ml.stats()
    assert s["feedback_loop"] is not None
    assert "n_updates" in s["feedback_loop"]
    await kb.close()


# ── MetaLearner.fit_clusterer ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fit_clusterer_noop_when_not_enough_endpoints(tmp_path: Path):
    """Clusterer k=8 ne fit pas avec 3 endpoints."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    snap = _make_snapshot(n_endpoints=3)
    await ml.fit_clusterer(snap)
    # k=8 > 3 → pas de fit, is_trained reste False
    if ml.endpoint_clusterer is not None:
        assert not ml.endpoint_clusterer.is_trained
    await kb.close()


@pytest.mark.asyncio
async def test_fit_clusterer_fits_with_enough_endpoints(tmp_path: Path):
    """Clusterer fit quand n_endpoints >= k."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    if ml.endpoint_clusterer is None:
        pytest.skip("EndpointClusterer non disponible")
    snap = _make_snapshot(n_endpoints=ml.endpoint_clusterer.k + 2)
    await ml.fit_clusterer(snap)
    assert ml.endpoint_clusterer.is_trained
    await kb.close()


# ── MetaLearner.apply_boosts ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_apply_boosts_no_classifier_returns_empty(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    ml._vuln_classifier = None
    ml._similarity_index = None
    snap = _make_snapshot()

    # Bus mock
    bus_mock = AsyncMock()
    bus_mock.emit = AsyncMock()
    boosts = await ml.apply_boosts(bus_mock, snap)
    assert boosts == {}
    await kb.close()


@pytest.mark.asyncio
async def test_apply_boosts_none_snapshot_returns_empty(tmp_path: Path):
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")
    bus_mock = AsyncMock()
    boosts = await ml.apply_boosts(bus_mock, None)
    assert boosts == {}
    await kb.close()


# ── MetaLearner.save_session ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_save_session_noop_when_no_findings(tmp_path: Path):
    """save_session avec findings=[] ne plante pas."""
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")

    oracle_mock = MagicMock()
    oracle_mock.oracle_results = {}
    oracle_mock.oracle_ml_model = None

    await ml.save_session(
        kb=kb,
        session_id="S-001",
        findings=[],
        oracle=oracle_mock,
        snapshot=_make_snapshot(),
        target_hash="h1",
        target_type="api",
    )
    await kb.close()


@pytest.mark.asyncio
async def test_save_session_saves_feedback_weights_when_updated(tmp_path: Path):
    """Après save_session avec FeedbackLoop mis à jour, les poids sont en KB."""
    from hdwp.core.ml.models.feedback_loop import V2_DIMENSIONS
    kb = _make_kb(tmp_path)
    ml = await MetaLearner.load(kb, target_hash="h1", target_type="api")

    # Simuler des updates FeedbackLoop
    fl = ml.feedback_loop
    assert fl is not None
    features = {dim: 0.5 for dim in V2_DIMENSIONS}
    for _ in range(3):
        fl.observe(features, "CONFIRMED")
    assert fl.n_updates == 3

    oracle_mock = MagicMock()
    oracle_mock.oracle_results = {}
    oracle_mock.oracle_ml_model = None

    await ml.save_session(
        kb=kb,
        session_id="S-001",
        findings=[],
        oracle=oracle_mock,
        snapshot=_make_snapshot(),
        target_hash="h1",
        target_type="api",
    )

    # Les poids doivent être persistés par target
    saved = await kb.get_feedback_weights_for_target("h1")
    assert saved is not None
    assert saved["n_updates"] == 3
    await kb.close()
