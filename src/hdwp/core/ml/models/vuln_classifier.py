# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
VulnClassifier — Phase 2 V4.

Classifieur multi-label entraîné sur EndpointEmbeddings (30D) pour prédire
P(vuln_type) par endpoint.

Architecture :
  MultiOutputClassifier(RandomForestClassifier) — une forêt binaire par vuln type.
  Chaque modèle prédit P(vuln_type=1) pour un endpoint donné.

Cycle de vie :
  1. Collecte : findings confirmés → store_vuln_sample() dans KB
  2. Entraînement auto après MIN_SAMPLES_FOR_TRAINING samples
  3. Déploiement : engine.py appelle predict() après observation pour chaque endpoint
  4. Agrégation par PropertyType → boost dans HypothesisPrioritizer

ADR-ML-003 : le VulnClassifier oriente la priorité, pas la décision finale.
ADR-ML-004 : chaque vuln type est appris indépendamment (multi-output, pas multi-class).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_VULN_MODEL_PATH = Path.home() / ".hdwp" / "vuln_classifier.joblib"
MIN_SAMPLES_FOR_TRAINING = 20

# Vuln types couverts — ordre stable pour binarisation
VULN_TYPES: list[str] = [
    "bola",
    "authz",
    "jwt",
    "cors",
    "sqli",
    "xss",
    "ssrf",
    "path_traversal",
    "http_smuggling",
]

# Mapping vuln type → property type (valeur de l'enum PropertyType)
VULN_TO_PROPERTY_TYPE: dict[str, str] = {
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
class VulnTrainingResult:
    n_samples: int
    vuln_types_trained: list[str]
    trained: bool = True
    error: str = ""


@dataclass
class VulnClassifierState:
    is_trained: bool = False
    n_samples_trained: int = 0
    vuln_types: list[str] = field(default_factory=list)
    model_path: str = ""


class VulnClassifier:
    """
    Classifieur multi-label sur EndpointEmbeddings (30D).

    Dégradation silencieuse si scikit-learn non installé ou modèle non entraîné :
    predict() retourne des probabilités nulles pour tous les vuln types.
    """

    def __init__(self, model_path: Path | str | None = None) -> None:
        self._model_path = Path(model_path) if model_path else DEFAULT_VULN_MODEL_PATH
        self._clf: Any = None       # sklearn MultiOutputClassifier
        self._is_trained: bool = False
        self._n_samples_trained: int = 0
        self._vuln_types: list[str] = list(VULN_TYPES)

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, endpoint_embedding: list[float]) -> dict[str, float]:
        """
        Prédit P(vuln_type) pour chaque vuln type connu.

        Retourne des probabilités nulles si le modèle n'est pas entraîné.
        """
        if not self._is_trained or self._clf is None:
            return {vt: 0.0 for vt in self._vuln_types}
        try:
            import numpy as np
            x = np.array(endpoint_embedding, dtype=float).reshape(1, -1)
            # MultiOutputClassifier.predict_proba retourne une liste de tableaux (un par label)
            probas = self._clf.predict_proba(x)
            result: dict[str, float] = {}
            for i, vt in enumerate(self._vuln_types):
                if i < len(probas):
                    # Chaque élément est shape (1, n_classes); P(positive) = classe index 1
                    clf_i = self._clf.estimators_[i]
                    classes = clf_i.classes_
                    if len(classes) == 2:
                        result[vt] = float(probas[i][0][1])
                    elif len(classes) == 1:
                        # Seulement une classe dans les données d'entraînement
                        result[vt] = float(classes[0])
                    else:
                        result[vt] = 0.0
                else:
                    result[vt] = 0.0
            return result
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln_classifier.predict_failed: %s", exc)
            return {vt: 0.0 for vt in self._vuln_types}

    def train(self, samples: list[dict[str, Any]]) -> VulnTrainingResult:
        """
        Entraîne le classifieur multi-label.

        Chaque sample doit avoir :
          - endpoint_embedding: list[float]  (30D)
          - vuln_labels: dict[str, float]    (vuln_type → 0.0/1.0 ou probabilité)
        """
        if len(samples) < MIN_SAMPLES_FOR_TRAINING:
            return VulnTrainingResult(
                n_samples=len(samples),
                vuln_types_trained=[],
                trained=False,
                error=f"Pas assez d'échantillons : {len(samples)} < {MIN_SAMPLES_FOR_TRAINING}",
            )
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.multioutput import MultiOutputClassifier

            X = np.array([s["endpoint_embedding"] for s in samples], dtype=float)

            # Construire la matrice Y (n_samples, n_vuln_types)
            # Binarise : > 0.5 → positive
            Y = np.zeros((len(samples), len(self._vuln_types)), dtype=int)
            for i, s in enumerate(samples):
                labels: dict[str, float] = s.get("vuln_labels", {})
                for j, vt in enumerate(self._vuln_types):
                    Y[i, j] = 1 if labels.get(vt, 0.0) > 0.5 else 0

            # Garde uniquement les colonnes qui ont les deux classes représentées
            valid_cols = [
                j for j in range(len(self._vuln_types))
                if len(set(Y[:, j])) >= 2
            ]

            if not valid_cols:
                return VulnTrainingResult(
                    n_samples=len(samples),
                    vuln_types_trained=[],
                    trained=False,
                    error="Aucun vuln type n'a les deux classes représentées",
                )

            valid_vuln_types = [self._vuln_types[j] for j in valid_cols]
            Y_valid = Y[:, valid_cols]

            base_clf = RandomForestClassifier(
                n_estimators=50,
                max_depth=8,
                random_state=42,
                class_weight="balanced",
            )
            clf = MultiOutputClassifier(base_clf)
            clf.fit(X, Y_valid)

            self._clf = clf
            self._is_trained = True
            self._n_samples_trained = len(samples)
            self._vuln_types = valid_vuln_types

            log.info(
                "vuln_classifier.trained n=%d vuln_types=%s",
                len(samples), valid_vuln_types,
            )
            return VulnTrainingResult(
                n_samples=len(samples),
                vuln_types_trained=valid_vuln_types,
            )
        except ImportError:
            return VulnTrainingResult(
                n_samples=len(samples),
                vuln_types_trained=[],
                trained=False,
                error="scikit-learn non installé",
            )
        except Exception as exc:  # noqa: BLE001
            return VulnTrainingResult(
                n_samples=len(samples),
                vuln_types_trained=[],
                trained=False,
                error=str(exc),
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
                "n_samples_trained": self._n_samples_trained,
                "vuln_types": self._vuln_types,
            }
            joblib.dump(payload, self._model_path)
            log.info("vuln_classifier.saved path=%s", self._model_path)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln_classifier.save_failed: %s", exc)
            return False

    def load(self) -> bool:
        """Charge le modèle depuis disque. Retourne True si succès."""
        if not self._model_path.exists():
            return False
        try:
            import joblib
            payload = joblib.load(self._model_path)
            self._clf = payload["clf"]
            self._n_samples_trained = payload["n_samples_trained"]
            self._vuln_types = payload["vuln_types"]
            self._is_trained = True
            log.info(
                "vuln_classifier.loaded n=%d vuln_types=%s",
                self._n_samples_trained, self._vuln_types,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln_classifier.load_failed: %s", exc)
            return False

    def property_type_boosts(self, endpoint_embedding: list[float]) -> dict[str, float]:
        """
        Retourne un facteur de boost par PropertyType (valeur str).

        Agrège les probabilités des vuln types via VULN_TO_PROPERTY_TYPE.
        Ex: boost["authorization"] = max(P(bola), P(authz), P(jwt))
        Retourne des 1.0 si le modèle n'est pas entraîné.
        """
        predictions = self.predict(endpoint_embedding)
        if all(v == 0.0 for v in predictions.values()):
            return {}

        # Groupe par property type — prend le max par groupe
        grouped: dict[str, float] = {}
        for vt, proba in predictions.items():
            pt = VULN_TO_PROPERTY_TYPE.get(vt, "integrity")
            grouped[pt] = max(grouped.get(pt, 0.0), proba)

        return grouped

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def n_samples_trained(self) -> int:
        return self._n_samples_trained

    @property
    def vuln_types(self) -> list[str]:
        return list(self._vuln_types)

    @property
    def state(self) -> VulnClassifierState:
        return VulnClassifierState(
            is_trained=self._is_trained,
            n_samples_trained=self._n_samples_trained,
            vuln_types=list(self._vuln_types),
            model_path=str(self._model_path),
        )
