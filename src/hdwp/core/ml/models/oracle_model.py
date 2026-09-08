# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
OracleModel — Phase 1 V4.

MLP entraîné sur DiffEmbeddings (51D) pour prédire la probabilité de verdict.
Nécessite le groupe [ml] : numpy + scikit-learn.

Cycle de vie :
  1. Collecte passive via KnowledgeBase (training_samples_oracle)
  2. Entraînement quand MIN_SAMPLES_FOR_TRAINING atteint
  3. Déploiement dans SemanticOracle en A/B avec le score V2
  4. Réentraînement après chaque N nouvelles sessions validées

ADR-ML-001 : le modèle ne peut pas confirmer seul — son score est combiné
avec les règles déterministes V3 via max(OracleModel, V2).
ADR-ML-002 : réentraînement uniquement sur données validées humainement
ou par outil indépendant (human_validated=True dans training_samples_oracle).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_ORACLE_MODEL_PATH = Path.home() / ".hdwp" / "oracle_model.joblib"
MIN_SAMPLES_FOR_TRAINING = 30
MLP_HIDDEN_LAYERS = (256, 128, 64)
VERDICT_LABELS = ["CONFIRMED", "REFUTED", "AMBIGUOUS"]


@dataclass
class TrainingResult:
    n_samples: int
    val_accuracy: float
    class_distribution: dict[str, int]
    trained: bool = True
    error: str = ""


@dataclass
class OracleModelState:
    is_trained: bool = False
    n_samples_trained: int = 0
    val_accuracy: float = 0.0
    model_path: str = ""


class OracleModel:
    """
    MLP (scikit-learn) entraîné sur DiffEmbeddings pour prédire P(verdict).

    Dégradation silencieuse si scikit-learn non installé ou modèle non entraîné :
    predict() retourne des scores neutres (0.0).
    """

    def __init__(self, model_path: Path | str | None = None) -> None:
        self._model_path = Path(model_path) if model_path else DEFAULT_ORACLE_MODEL_PATH
        self._clf: Any = None          # sklearn MLPClassifier
        self._label_enc: Any = None    # sklearn LabelEncoder
        self._is_trained: bool = False
        self._n_samples_trained: int = 0
        self._val_accuracy: float = 0.0

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, diff_embedding: list[float]) -> dict[str, float]:
        """
        Prédit P(CONFIRMED), P(REFUTED), P(AMBIGUOUS) pour un DiffEmbedding.
        Retourne des scores nuls si le modèle n'est pas entraîné.
        """
        if not self._is_trained or self._clf is None:
            return {"confirmed": 0.0, "refuted": 0.0, "ambiguous": 0.0}
        try:
            import numpy as np
            x = np.array(diff_embedding, dtype=float).reshape(1, -1)
            proba = self._clf.predict_proba(x)[0]
            # clf.classes_ contient des entiers (sortie de LabelEncoder)
            # on inverse via _label_enc pour retrouver les labels texte
            labels = self._label_enc.inverse_transform(self._clf.classes_)
            result = {"confirmed": 0.0, "refuted": 0.0, "ambiguous": 0.0}
            for i, label in enumerate(labels):
                key = str(label).lower()
                if key in result:
                    result[key] = float(proba[i])
            return result
        except Exception as exc:  # noqa: BLE001
            log.warning("oracle_model.predict_failed: %s", exc)
            return {"confirmed": 0.0, "refuted": 0.0, "ambiguous": 0.0}

    def train(self, samples: list[dict[str, Any]]) -> TrainingResult:
        """
        Entraîne le MLP sur les échantillons fournis.

        Chaque sample doit avoir : diff_embedding (list[float]), verdict (str).
        Requiert >= MIN_SAMPLES_FOR_TRAINING échantillons.
        """
        if len(samples) < MIN_SAMPLES_FOR_TRAINING:
            return TrainingResult(
                n_samples=len(samples),
                val_accuracy=0.0,
                class_distribution={},
                trained=False,
                error=f"Pas assez d'échantillons : {len(samples)} < {MIN_SAMPLES_FOR_TRAINING}",
            )
        try:
            import numpy as np
            from sklearn.model_selection import train_test_split
            from sklearn.neural_network import MLPClassifier
            from sklearn.preprocessing import LabelEncoder

            X = np.array([s["diff_embedding"] for s in samples], dtype=float)
            y_raw = [s["verdict"] for s in samples]

            enc = LabelEncoder()
            y = enc.fit_transform(y_raw)

            dist = {label: int(y_raw.count(label)) for label in VERDICT_LABELS if label in y_raw}

            # Split 80/20 avec validation hors-sample pour tous les jeux >= MIN_SAMPLES.
            # stratify=y uniquement si toutes les classes ont >= 2 membres (évite ValueError).
            min_class_count = min(dist.values()) if dist else 0
            use_stratify = min_class_count >= 2
            try:
                X_train, X_val, y_train, y_val = train_test_split(
                    X, y, test_size=0.2, random_state=42,
                    stratify=y if use_stratify else None,
                )
            except ValueError:
                # Fallback sans stratification si une classe reste trop rare après split
                X_train, X_val, y_train, y_val = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )

            clf = MLPClassifier(
                hidden_layer_sizes=MLP_HIDDEN_LAYERS,
                activation="relu",
                max_iter=500,
                random_state=42,
                early_stopping=True,
                validation_fraction=0.1 if len(X_train) >= 20 else 0.0,
                n_iter_no_change=10,
            )
            clf.fit(X_train, y_train)
            val_acc = float(clf.score(X_val, y_val))

            self._clf = clf
            self._label_enc = enc
            self._is_trained = True
            self._n_samples_trained = len(samples)
            self._val_accuracy = val_acc

            log.info(
                "oracle_model.trained n=%d val_acc=%.3f classes=%s",
                len(samples), val_acc, list(enc.classes_),
            )
            return TrainingResult(
                n_samples=len(samples),
                val_accuracy=val_acc,
                class_distribution=dist,
            )
        except ImportError:
            return TrainingResult(
                n_samples=len(samples), val_accuracy=0.0, class_distribution={},
                trained=False, error="scikit-learn non installé",
            )
        except Exception as exc:  # noqa: BLE001
            return TrainingResult(
                n_samples=len(samples), val_accuracy=0.0, class_distribution={},
                trained=False, error=str(exc),
            )

    def save(self) -> bool:
        """Persiste le modèle sur disque. Retourne True si succès."""
        if not self._is_trained or self._clf is None:
            return False
        try:
            import joblib
            self._model_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "clf": self._clf,
                "label_enc": self._label_enc,
                "n_samples_trained": self._n_samples_trained,
                "val_accuracy": self._val_accuracy,
            }
            joblib.dump(payload, self._model_path)
            log.info("oracle_model.saved path=%s", self._model_path)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("oracle_model.save_failed: %s", exc)
            return False

    def load(self) -> bool:
        """Charge le modèle depuis disque. Retourne True si succès."""
        if not self._model_path.exists():
            return False
        try:
            import joblib
            payload = joblib.load(self._model_path)
            self._clf = payload["clf"]
            self._label_enc = payload["label_enc"]
            self._n_samples_trained = payload["n_samples_trained"]
            self._val_accuracy = payload["val_accuracy"]
            self._is_trained = True
            log.info(
                "oracle_model.loaded n=%d val_acc=%.3f",
                self._n_samples_trained, self._val_accuracy,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("oracle_model.load_failed: %s", exc)
            return False

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def n_samples_trained(self) -> int:
        return self._n_samples_trained

    @property
    def val_accuracy(self) -> float:
        return self._val_accuracy

    @property
    def state(self) -> OracleModelState:
        return OracleModelState(
            is_trained=self._is_trained,
            n_samples_trained=self._n_samples_trained,
            val_accuracy=self._val_accuracy,
            model_path=str(self._model_path),
        )
