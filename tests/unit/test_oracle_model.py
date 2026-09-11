# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests de l'OracleModel — Phase 1 V4."""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path

import pytest

_has_sklearn = importlib.util.find_spec("sklearn") is not None
_needs_sklearn = pytest.mark.skipif(not _has_sklearn, reason="scikit-learn not installed")

from hdwp.core.ml.models.oracle_model import (
    MIN_SAMPLES_FOR_TRAINING,
    OracleModel,
    TrainingResult,
)


# ── Factories ─────────────────────────────────────────────────────────────────

def _make_sample(verdict: str, seed: int = 0) -> dict:
    """Génère un sample synthétique reproductible."""
    rng = random.Random(seed)
    base = [rng.uniform(0, 1) for _ in range(51)]
    # Différenciation des classes : CONFIRMED → timing diff élevé
    if verdict == "CONFIRMED":
        base[50] = rng.uniform(0.7, 1.0)   # timing diff élevé
        base[46] = 1.0                       # status_diff
    elif verdict == "REFUTED":
        base[50] = rng.uniform(-0.1, 0.1)
        base[46] = 0.0
    else:  # AMBIGUOUS
        base[50] = rng.uniform(0.3, 0.6)
        base[46] = rng.choice([0.0, 1.0])
    return {"diff_embedding": base, "verdict": verdict}


def _make_dataset(
    n_confirmed: int = 15,
    n_refuted: int = 15,
    n_ambiguous: int = 5,
) -> list[dict]:
    samples = []
    for i in range(n_confirmed):
        samples.append(_make_sample("CONFIRMED", seed=i))
    for i in range(n_refuted):
        samples.append(_make_sample("REFUTED", seed=100 + i))
    for i in range(n_ambiguous):
        samples.append(_make_sample("AMBIGUOUS", seed=200 + i))
    return samples


# ── State ─────────────────────────────────────────────────────────────────────

def test_initial_state_not_trained():
    model = OracleModel()
    assert not model.is_trained
    assert model.n_samples_trained == 0
    assert model.val_accuracy == 0.0


def test_predict_returns_zeros_when_untrained():
    model = OracleModel()
    pred = model.predict([0.0] * 51)
    assert pred["confirmed"] == pytest.approx(0.0)
    assert pred["refuted"] == pytest.approx(0.0)
    assert pred["ambiguous"] == pytest.approx(0.0)


def test_predict_returns_dict_with_three_keys():
    model = OracleModel()
    pred = model.predict([0.5] * 51)
    assert set(pred.keys()) == {"confirmed", "refuted", "ambiguous"}


# ── Insufficient data ─────────────────────────────────────────────────────────

def test_train_fails_below_min_samples():
    model = OracleModel()
    few = [_make_sample("CONFIRMED", i) for i in range(5)]
    result = model.train(few)
    assert not result.trained
    assert result.n_samples == 5
    assert "Pas assez" in result.error


def test_train_returns_training_result():
    model = OracleModel()
    result = model.train([])
    assert isinstance(result, TrainingResult)
    assert not result.trained


# ── Training ──────────────────────────────────────────────────────────────────

@_needs_sklearn
def test_train_succeeds_with_enough_samples():
    model = OracleModel()
    samples = _make_dataset(n_confirmed=15, n_refuted=15, n_ambiguous=5)
    result = model.train(samples)
    assert result.trained
    assert result.n_samples == 35
    assert model.is_trained


@_needs_sklearn
def test_train_sets_n_samples_trained():
    model = OracleModel()
    samples = _make_dataset()
    model.train(samples)
    assert model.n_samples_trained == len(samples)


@_needs_sklearn
def test_train_val_accuracy_reasonable():
    model = OracleModel()
    samples = _make_dataset(n_confirmed=20, n_refuted=20, n_ambiguous=5)
    result = model.train(samples)
    assert result.trained
    assert 0.0 <= result.val_accuracy <= 1.0


@_needs_sklearn
def test_class_distribution_in_result():
    model = OracleModel()
    samples = _make_dataset(n_confirmed=15, n_refuted=15, n_ambiguous=5)
    result = model.train(samples)
    assert result.trained
    assert "CONFIRMED" in result.class_distribution
    assert result.class_distribution["CONFIRMED"] == 15
    assert result.class_distribution["REFUTED"] == 15


# ── Predict after training ─────────────────────────────────────────────────────

@_needs_sklearn
def test_predict_returns_probabilities_after_training():
    model = OracleModel()
    samples = _make_dataset()
    model.train(samples)
    pred = model.predict([0.5] * 51)
    total = sum(pred.values())
    assert total == pytest.approx(1.0, abs=0.01)


@_needs_sklearn
def test_predict_confirmed_sample_leans_confirmed():
    """Un échantillon CONFIRMED doit avoir P(confirmed) élevé après entraînement."""
    model = OracleModel()
    samples = _make_dataset(n_confirmed=40, n_refuted=40, n_ambiguous=10)
    model.train(samples)
    confirmed_emb = _make_sample("CONFIRMED", seed=999)["diff_embedding"]
    pred = model.predict(confirmed_emb)
    assert pred["confirmed"] > pred["refuted"]


@_needs_sklearn
def test_predict_refuted_sample_leans_refuted():
    model = OracleModel()
    samples = _make_dataset(n_confirmed=40, n_refuted=40, n_ambiguous=10)
    model.train(samples)
    refuted_emb = _make_sample("REFUTED", seed=888)["diff_embedding"]
    pred = model.predict(refuted_emb)
    assert pred["refuted"] > pred["confirmed"]


@_needs_sklearn
def test_predict_deterministic():
    model = OracleModel()
    samples = _make_dataset()
    model.train(samples)
    emb = [0.3] * 51
    assert model.predict(emb) == model.predict(emb)


# ── Persistence ───────────────────────────────────────────────────────────────

@_needs_sklearn
def test_save_and_load(tmp_path: Path):
    model_path = tmp_path / "oracle.joblib"
    model = OracleModel(model_path=model_path)
    samples = _make_dataset()
    model.train(samples)
    assert model.save()

    loaded = OracleModel(model_path=model_path)
    assert loaded.load()
    assert loaded.is_trained
    assert loaded.n_samples_trained == model.n_samples_trained

    # Même prédiction
    emb = [0.4] * 51
    assert loaded.predict(emb) == pytest.approx(model.predict(emb), abs=1e-6)


def test_save_returns_false_when_untrained():
    model = OracleModel()
    assert not model.save()


def test_load_returns_false_when_file_missing(tmp_path: Path):
    model = OracleModel(model_path=tmp_path / "nonexistent.joblib")
    assert not model.load()


def test_state_property():
    model = OracleModel()
    state = model.state
    assert not state.is_trained
    assert state.n_samples_trained == 0


# ── KB integration ────────────────────────────────────────────────────────────

@_needs_sklearn
@pytest.mark.asyncio
async def test_kb_train_oracle_model(tmp_path: Path):
    from hdwp.core.knowledge.base import KnowledgeBase

    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    # Stocker assez de samples
    for i in range(MIN_SAMPLES_FOR_TRAINING + 5):
        verdict = "CONFIRMED" if i % 2 == 0 else "REFUTED"
        emb = _make_sample(verdict, seed=i)["diff_embedding"]
        await kb.store_oracle_sample(emb, "identity_swap", verdict, f"S-{i:03d}")

    model = OracleModel(model_path=tmp_path / "oracle.joblib")
    result = await kb.train_oracle_model(model, only_validated=False)
    assert result is not None
    assert result.trained
    assert model.is_trained
    await kb.close()


@pytest.mark.asyncio
async def test_kb_train_oracle_model_insufficient_data(tmp_path: Path):
    from hdwp.core.knowledge.base import KnowledgeBase

    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_oracle_sample([0.1] * 51, "bola", "CONFIRMED", "S-001")
    model = OracleModel(model_path=tmp_path / "oracle.joblib")
    result = await kb.train_oracle_model(model, only_validated=False)
    assert result is not None
    assert not result.trained
    await kb.close()
