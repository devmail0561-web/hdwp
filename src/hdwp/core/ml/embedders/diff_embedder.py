# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.ml.embedders.response_embedder import ResponseEmbedder
from hdwp.core.model.schemas import NormalizedResponse, SemanticDiff


class DiffEmbedder:
    """
    Encode la différence entre une réponse baseline et une réponse expérimentale.
    Vecteur d'entrée principal de l'OracleModel (Phase 1).

    Layout (DIM=51) :
      [0:22]  e - b  (différence directionnelle par feature ResponseEmbedder)
      [22:44] |e - b| (magnitude du changement)
      [44]    structural_difference (bool depuis SemanticDiff ou déduit)
      [45]    behavioral_difference (bool)
      [46]    status_difference (bool)
      [47]    leaked_fields count normalisé (/ 10.0, clamped [0, 1])
      [48]    data_identity_score (0.5 si None → inconnu)
      [49]    suspicious_fields count normalisé (/ 5.0, clamped [0, 1])
      [50]    timing diff normalisé ((exp - base) / max(base, 1), clamped [-1, 1])
    """

    DIM: int = 51

    def __init__(self) -> None:
        self._re = ResponseEmbedder()

    def embed(
        self,
        baseline: NormalizedResponse,
        experiment: NormalizedResponse,
        diff: SemanticDiff | None = None,
    ) -> list[float]:
        b = self._re.embed(baseline)
        e = self._re.embed(experiment)

        # [0:22] directional diff
        diff_vec = [ei - bi for ei, bi in zip(e, b)]
        # [22:44] magnitude
        abs_vec = [abs(v) for v in diff_vec]

        # [44:50] structural bits
        if diff is not None:
            struct_bit = 1.0 if diff.structural_difference else 0.0
            behav_bit = 1.0 if diff.behavioral_difference else 0.0
            status_bit = 1.0 if diff.status_difference else 0.0
            leaked_n = min(len(diff.leaked_fields) / 10.0, 1.0)
            identity = diff.data_identity_score if diff.data_identity_score is not None else 0.5
            suspicious = min(len(diff.suspicious_fields) / 5.0, 1.0)
        else:
            struct_bit = 0.0
            behav_bit = 0.0
            status_bit = 1.0 if baseline.status_code != experiment.status_code else 0.0
            leaked_n = 0.0
            identity = 0.5
            suspicious = 0.0

        # [50] timing diff
        base_t = max(baseline.timing_ms, 1.0)
        timing_d = max(-1.0, min(1.0, (experiment.timing_ms - base_t) / base_t))

        vec = diff_vec + abs_vec + [
            struct_bit, behav_bit, status_bit,
            leaked_n, identity, suspicious,
            timing_d,
        ]

        assert len(vec) == self.DIM, f"DiffEmbedder: dim={len(vec)} != {self.DIM}"
        return vec
