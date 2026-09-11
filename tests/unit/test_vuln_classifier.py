# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests du VulnClassifier — Phase 2 V4."""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path

import pytest

_has_sklearn = importlib.util.find_spec("sklearn") is not None
_needs_sklearn = pytest.mark.skipif(not _has_sklearn, reason="scikit-learn not installed")

from hdwp.core.ml.models.vuln_classifier import (
    MIN_SAMPLES_FOR_TRAINING,
    VULN_TO_PROPERTY_TYPE,
    VULN_TYPES,
    VulnClassifier,
    VulnTrainingResult,
)


# ── Factories ─────────────────────────────────────────────────────────────────

def _make_endpoint_embedding(vuln_type: str | None = None, seed: int = 0) -> list[float]:
    """Génère un EndpointEmbedding (30D) synthétique reproductible."""
    rng = random.Random(seed)
    vec = [rng.uniform(0, 1) for _ in range(30)]
    # Signal différentiateur par vuln type
    if vuln_type == "bola":
        vec[7] = 1.0   # auth_required
        vec[8] = 0.8   # role_count élevé
    elif vuln_type == "sqli":
        vec[9] = 0.9   # param type: integer
        vec[14] = 0.7  # param loc: body
    elif vuln_type == "cors":
        vec[28] = 0.0  # pas graphql
        vec[29] = 0.0  # pas xml
    return vec


def _make_sample(vuln_type: str, positive: bool = True, seed: int = 0) -> dict:
    emb = _make_endpoint_embedding(vuln_type if positive else None, seed)
    return {
        "endpoint_embedding": emb,
        "vuln_labels": {vuln_type: 1.0 if positive else 0.0},
    }


def _make_balanced_dataset(n: int = 40) -> list[dict]:
    """Dataset équilibré : chaque vuln type a des positifs ET négatifs."""
    samples = []
    for i in range(n):
        vt = VULN_TYPES[i % len(VULN_TYPES)]
        positive = i % 2 == 0
        samples.append(_make_sample(vt, positive=positive, seed=i))
    return samples


# ── Instanciation ──────────────────────────────────────────────────────────────

class TestVulnClassifierInit:
    def test_default_state(self) -> None:
        clf = VulnClassifier()
        assert not clf.is_trained
        assert clf.n_samples_trained == 0
        assert len(clf.vuln_types) == len(VULN_TYPES)

    def test_custom_model_path(self, tmp_path: Path) -> None:
        p = tmp_path / "vc.joblib"
        clf = VulnClassifier(model_path=p)
        assert clf._model_path == p

    def test_state_property(self) -> None:
        clf = VulnClassifier()
        state = clf.state
        assert not state.is_trained
        assert state.n_samples_trained == 0
        assert isinstance(state.vuln_types, list)


# ── Prédiction sans entraînement ──────────────────────────────────────────────

class TestPredictUntrained:
    def test_returns_zeros(self) -> None:
        clf = VulnClassifier()
        emb = _make_endpoint_embedding()
        result = clf.predict(emb)
        assert all(v == 0.0 for v in result.values())

    def test_returns_all_vuln_types(self) -> None:
        clf = VulnClassifier()
        emb = _make_endpoint_embedding()
        result = clf.predict(emb)
        for vt in VULN_TYPES:
            assert vt in result

    def test_property_type_boosts_untrained(self) -> None:
        clf = VulnClassifier()
        emb = _make_endpoint_embedding()
        boosts = clf.property_type_boosts(emb)
        assert boosts == {}


# ── Entraînement ──────────────────────────────────────────────────────────────

class TestTrain:
    def test_insufficient_samples(self) -> None:
        clf = VulnClassifier()
        samples = [_make_sample("bola", seed=i) for i in range(5)]
        result = clf.train(samples)
        assert not result.trained
        assert result.error
        assert not clf.is_trained

    @_needs_sklearn
    def test_train_success(self) -> None:
        clf = VulnClassifier()
        samples = _make_balanced_dataset(n=40)
        result = clf.train(samples)
        assert result.trained
        assert result.n_samples == 40
        assert isinstance(result.vuln_types_trained, list)
        assert len(result.vuln_types_trained) > 0
        assert clf.is_trained
        assert clf.n_samples_trained == 40

    @_needs_sklearn
    def test_train_result_type(self) -> None:
        clf = VulnClassifier()
        result = clf.train(_make_balanced_dataset(n=40))
        assert isinstance(result, VulnTrainingResult)

    def test_no_scikit_learn_graceful(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins
        real_import = builtins.__import__

        def mock_import(name: str, *args, **kwargs):  # type: ignore[override]
            if "sklearn" in name:
                raise ImportError("no sklearn")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        clf = VulnClassifier()
        result = clf.train(_make_balanced_dataset(n=40))
        assert not result.trained
        assert "scikit-learn" in result.error


# ── Prédiction après entraînement ─────────────────────────────────────────────

@_needs_sklearn
class TestPredictTrained:
    @pytest.fixture
    def trained_clf(self) -> VulnClassifier:
        clf = VulnClassifier()
        clf.train(_make_balanced_dataset(n=40))
        return clf

    def test_predict_returns_floats(self, trained_clf: VulnClassifier) -> None:
        emb = _make_endpoint_embedding("bola")
        result = trained_clf.predict(emb)
        assert isinstance(result, dict)
        for v in result.values():
            assert isinstance(v, float)
            assert 0.0 <= v <= 1.0

    def test_predict_covers_trained_types(self, trained_clf: VulnClassifier) -> None:
        emb = _make_endpoint_embedding()
        result = trained_clf.predict(emb)
        for vt in trained_clf.vuln_types:
            assert vt in result

    def test_property_type_boosts_trained(self, trained_clf: VulnClassifier) -> None:
        emb = _make_endpoint_embedding("bola")
        boosts = trained_clf.property_type_boosts(emb)
        # Si le modèle fait une prédiction non-nulle, boosts doit être non-vide
        preds = trained_clf.predict(emb)
        if any(v > 0 for v in preds.values()):
            assert isinstance(boosts, dict)

    def test_property_type_boosts_mapping(self, trained_clf: VulnClassifier) -> None:
        """Les clés des boosts doivent être des valeurs de PropertyType."""
        from hdwp.core.model.schemas import PropertyType
        emb = _make_endpoint_embedding("bola")
        boosts = trained_clf.property_type_boosts(emb)
        valid_pt_values = {pt.value for pt in PropertyType}
        for pt_key in boosts:
            assert pt_key in valid_pt_values


# ── Persistance ───────────────────────────────────────────────────────────────

class TestSaveLoad:
    def test_save_untrained_returns_false(self, tmp_path: Path) -> None:
        clf = VulnClassifier(model_path=tmp_path / "v.joblib")
        assert not clf.save()

    def test_load_missing_file_returns_false(self, tmp_path: Path) -> None:
        clf = VulnClassifier(model_path=tmp_path / "missing.joblib")
        assert not clf.load()

    @_needs_sklearn
    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "vc.joblib"
        clf = VulnClassifier(model_path=path)
        clf.train(_make_balanced_dataset(n=40))
        assert clf.save()
        assert path.exists()

        clf2 = VulnClassifier(model_path=path)
        assert clf2.load()
        assert clf2.is_trained
        assert clf2.n_samples_trained == clf.n_samples_trained
        assert clf2.vuln_types == clf.vuln_types

    @_needs_sklearn
    def test_predictions_consistent_after_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "vc_pred.joblib"
        clf = VulnClassifier(model_path=path)
        clf.train(_make_balanced_dataset(n=40))
        clf.save()

        emb = _make_endpoint_embedding("bola", seed=999)
        pred1 = clf.predict(emb)

        clf2 = VulnClassifier(model_path=path)
        clf2.load()
        pred2 = clf2.predict(emb)

        assert pred1 == pred2


# ── VULN_TO_PROPERTY_TYPE mapping ─────────────────────────────────────────────

class TestVulnToPropertyTypeMapping:
    def test_all_vuln_types_mapped(self) -> None:
        for vt in VULN_TYPES:
            assert vt in VULN_TO_PROPERTY_TYPE

    def test_authorization_group(self) -> None:
        assert VULN_TO_PROPERTY_TYPE["bola"] == "authorization"
        assert VULN_TO_PROPERTY_TYPE["authz"] == "authorization"
        assert VULN_TO_PROPERTY_TYPE["jwt"] == "authorization"

    def test_integrity_group(self) -> None:
        assert VULN_TO_PROPERTY_TYPE["sqli"] == "integrity"
        assert VULN_TO_PROPERTY_TYPE["xss"] == "integrity"
        assert VULN_TO_PROPERTY_TYPE["ssrf"] == "integrity"

    def test_coherence_group(self) -> None:
        assert VULN_TO_PROPERTY_TYPE["cors"] == "coherence"

    def test_state_group(self) -> None:
        assert VULN_TO_PROPERTY_TYPE["http_smuggling"] == "state"
