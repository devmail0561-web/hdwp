# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests unitaires — CrossSessionTransfer (V4 Sprint 9)."""
from __future__ import annotations

import pytest

from hdwp.core.ml.models.cross_session_transfer import (
    MIN_UPDATES_FOR_TRANSFER,
    TRANSFER_CROSS_TYPE,
    TRANSFER_EXACT,
    TRANSFER_SAME_TYPE,
    CrossSessionTransfer,
    _transfer_factor,
)
from hdwp.core.ml.models.feedback_loop import DEFAULT_BIAS, DEFAULT_WEIGHTS, V2_DIMENSIONS


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_snapshot(
    target_hash: str = "abc123",
    target_type: str = "api",
    n_updates: int = 10,
    weights: dict | None = None,
    bias: float = DEFAULT_BIAS,
) -> dict:
    return {
        "target_hash": target_hash,
        "target_type": target_type,
        "n_updates": n_updates,
        "weights": weights or dict(DEFAULT_WEIGHTS),
        "bias": bias,
    }


def _uniform_weights(value: float) -> dict[str, float]:
    return {dim: value for dim in V2_DIMENSIONS}


# ── _transfer_factor ─────────────────────────────────────────────────────────

class TestTransferFactor:
    def test_exact_same_hash(self):
        f = _transfer_factor("api", "api", "hash1", "hash1")
        assert f == TRANSFER_EXACT

    def test_same_type_different_hash(self):
        f = _transfer_factor("api", "api", "hash1", "hash2")
        assert f == TRANSFER_SAME_TYPE

    def test_cross_type(self):
        f = _transfer_factor("cms", "api", "hash1", "hash2")
        assert f == TRANSFER_CROSS_TYPE

    def test_empty_hash_falls_back_to_type(self):
        # hash vide → pas de comparaison exact, on compare les types
        f = _transfer_factor("graphql", "graphql", "", "hash2")
        assert f == TRANSFER_SAME_TYPE

    def test_both_empty_cross_type(self):
        f = _transfer_factor("", "", "", "")
        assert f == TRANSFER_CROSS_TYPE

    def test_exact_beats_same_type_with_matching_hash(self):
        # même hash ET même type → exact (1.0) prime sur same_type (0.7)
        f = _transfer_factor("api", "api", "same", "same")
        assert f == TRANSFER_EXACT


# ── CrossSessionTransfer.blend ────────────────────────────────────────────────

class TestBlend:
    def setup_method(self):
        self.cst = CrossSessionTransfer()

    def test_factor_1_returns_source(self):
        w_src = _uniform_weights(2.0)
        blended, bias = self.cst.blend(w_src, 1.0, transfer_factor=1.0)
        for dim in V2_DIMENSIONS:
            assert blended[dim] == pytest.approx(2.0, rel=1e-5)
        assert bias == pytest.approx(1.0, rel=1e-5)

    def test_factor_0_returns_defaults(self):
        w_src = _uniform_weights(2.0)
        blended, bias = self.cst.blend(w_src, -1.0, transfer_factor=0.0)
        for dim in V2_DIMENSIONS:
            assert blended[dim] == pytest.approx(DEFAULT_WEIGHTS[dim], rel=1e-5)
        assert bias == pytest.approx(DEFAULT_BIAS, rel=1e-5)

    def test_factor_half_interpolates(self):
        w_src = _uniform_weights(4.0)
        blended, _ = self.cst.blend(w_src, 0.0, transfer_factor=0.5)
        for dim in V2_DIMENSIONS:
            expected = 4.0 * 0.5 + DEFAULT_WEIGHTS[dim] * 0.5
            assert blended[dim] == pytest.approx(expected, rel=1e-4)

    def test_factor_clamped_above_1(self):
        w_src = _uniform_weights(3.0)
        blended, _ = self.cst.blend(w_src, 0.0, transfer_factor=2.0)
        # clamp → factor=1.0
        for dim in V2_DIMENSIONS:
            assert blended[dim] == pytest.approx(3.0, rel=1e-5)

    def test_factor_clamped_below_0(self):
        w_src = _uniform_weights(3.0)
        blended, _ = self.cst.blend(w_src, 0.0, transfer_factor=-1.0)
        # clamp → factor=0.0 → defaults
        for dim in V2_DIMENSIONS:
            assert blended[dim] == pytest.approx(DEFAULT_WEIGHTS[dim], rel=1e-5)

    def test_missing_source_dim_uses_default(self):
        # source dict vide → tous les dims tombent sur DEFAULT_WEIGHTS
        blended, _ = self.cst.blend({}, DEFAULT_BIAS, transfer_factor=1.0)
        for dim in V2_DIMENSIONS:
            # factor=1.0 + source absent → w_src = default → blended = default
            assert blended[dim] == pytest.approx(DEFAULT_WEIGHTS[dim], rel=1e-5)

    def test_returns_rounded_values(self):
        w_src = _uniform_weights(1.123456789)
        blended, bias = self.cst.blend(w_src, -3.987654321, transfer_factor=0.7)
        for v in blended.values():
            assert len(str(v).split(".")[-1]) <= 6
        assert len(str(abs(bias)).split(".")[-1]) <= 6


# ── CrossSessionTransfer.select_and_blend ─────────────────────────────────────

class TestSelectAndBlend:
    def setup_method(self):
        self.cst = CrossSessionTransfer()

    def test_empty_snapshots_returns_none(self):
        result = self.cst.select_and_blend([], "h1", "api")
        assert result is None

    def test_below_min_updates_returns_none(self):
        snap = _make_snapshot(n_updates=MIN_UPDATES_FOR_TRANSFER - 1)
        result = self.cst.select_and_blend([snap], "h2", "api")
        assert result is None

    def test_exact_match_returns_near_source(self):
        w_src = _uniform_weights(2.5)
        snap = _make_snapshot(target_hash="exact", target_type="api",
                              n_updates=20, weights=w_src, bias=-2.0)
        result = self.cst.select_and_blend([snap], dest_target_hash="exact", dest_target_type="api")
        assert result is not None
        # factor=1.0 → blended ≈ source
        for dim in V2_DIMENSIONS:
            assert result["weights"][dim] == pytest.approx(2.5, rel=1e-5)
        assert result["bias"] == pytest.approx(-2.0, rel=1e-5)

    def test_same_type_match_interpolates(self):
        w_src = _uniform_weights(3.0)
        snap = _make_snapshot(target_hash="other", target_type="api",
                              n_updates=15, weights=w_src)
        result = self.cst.select_and_blend([snap], dest_target_hash="new", dest_target_type="api")
        assert result is not None
        for dim in V2_DIMENSIONS:
            expected = 3.0 * TRANSFER_SAME_TYPE + DEFAULT_WEIGHTS[dim] * (1 - TRANSFER_SAME_TYPE)
            assert result["weights"][dim] == pytest.approx(expected, rel=1e-4)

    def test_cross_type_match_interpolates_weakly(self):
        w_src = _uniform_weights(3.0)
        snap = _make_snapshot(target_hash="other", target_type="cms",
                              n_updates=20, weights=w_src)
        result = self.cst.select_and_blend([snap], dest_target_hash="new", dest_target_type="api")
        assert result is not None
        for dim in V2_DIMENSIONS:
            expected = 3.0 * TRANSFER_CROSS_TYPE + DEFAULT_WEIGHTS[dim] * (1 - TRANSFER_CROSS_TYPE)
            assert result["weights"][dim] == pytest.approx(expected, rel=1e-4)

    def test_n_updates_reset_to_zero(self):
        snap = _make_snapshot(n_updates=50)
        result = self.cst.select_and_blend([snap], "new", "api")
        assert result is not None
        # n_updates doit être 0 — la session courante commence proprement
        assert result["n_updates"] == 0

    def test_prefers_exact_over_same_type(self):
        same_type = _make_snapshot(target_hash="other", target_type="api",
                                   n_updates=100, weights=_uniform_weights(3.0))
        exact = _make_snapshot(target_hash="dest", target_type="api",
                               n_updates=10, weights=_uniform_weights(2.0))
        result = self.cst.select_and_blend(
            [same_type, exact], dest_target_hash="dest", dest_target_type="api"
        )
        assert result is not None
        # exact → factor=1.0 → blended ≈ 2.0 (pas 3.0 du same_type)
        for dim in V2_DIMENSIONS:
            assert result["weights"][dim] == pytest.approx(2.0, rel=1e-5)

    def test_among_same_factor_picks_most_updates(self):
        low = _make_snapshot(target_hash="a", target_type="api",
                             n_updates=10, weights=_uniform_weights(1.0))
        high = _make_snapshot(target_hash="b", target_type="api",
                              n_updates=50, weights=_uniform_weights(4.0))
        result = self.cst.select_and_blend(
            [low, high], dest_target_hash="dest", dest_target_type="api"
        )
        assert result is not None
        # même factor (same_type pour les deux) → préfère high (n=50)
        for dim in V2_DIMENSIONS:
            expected = 4.0 * TRANSFER_SAME_TYPE + DEFAULT_WEIGHTS[dim] * (1 - TRANSFER_SAME_TYPE)
            assert result["weights"][dim] == pytest.approx(expected, rel=1e-4)

    def test_result_compatible_with_feedback_loop_load(self):
        from hdwp.core.ml.models.feedback_loop import FeedbackLoop
        snap = _make_snapshot(n_updates=20)
        result = self.cst.select_and_blend([snap], "new_hash", "graphql")
        assert result is not None
        fl = FeedbackLoop()
        fl.load_serializable(result)
        # n_updates=0 car on hérite des poids mais pas de l'historique d'updates
        assert fl.n_updates == 0
        for dim in V2_DIMENSIONS:
            assert dim in fl.current_weights()

    def test_all_below_min_updates_returns_none(self):
        snaps = [
            _make_snapshot(target_hash=f"h{i}", n_updates=i)
            for i in range(MIN_UPDATES_FOR_TRANSFER)
        ]
        result = self.cst.select_and_blend(snaps, "new", "api")
        assert result is None

    def test_only_eligible_snapshots_considered(self):
        ineligible = _make_snapshot(target_hash="exact", target_type="api",
                                    n_updates=MIN_UPDATES_FOR_TRANSFER - 1,
                                    weights=_uniform_weights(5.0))
        eligible = _make_snapshot(target_hash="other", target_type="cms",
                                  n_updates=MIN_UPDATES_FOR_TRANSFER,
                                  weights=_uniform_weights(2.0))
        result = self.cst.select_and_blend(
            [ineligible, eligible], dest_target_hash="exact", dest_target_type="api"
        )
        # ineligible (exact match) est écarté ; eligible (cross_type) utilisé
        assert result is not None
        for dim in V2_DIMENSIONS:
            expected = 2.0 * TRANSFER_CROSS_TYPE + DEFAULT_WEIGHTS[dim] * (1 - TRANSFER_CROSS_TYPE)
            assert result["weights"][dim] == pytest.approx(expected, rel=1e-4)


# ── Intégration FeedbackLoop ──────────────────────────────────────────────────

class TestCrossSessionTransferIntegration:
    """Vérifie que le transfert produit de meilleurs poids initiaux que les défauts."""

    def test_transferred_weights_closer_to_source_than_defaults(self):
        # Si on a appris sur un API similaire, les poids transférés
        # doivent être plus proches de la source que des défauts.
        w_src = {dim: DEFAULT_WEIGHTS[dim] * 1.5 for dim in V2_DIMENSIONS}
        snap = _make_snapshot(target_hash="src", target_type="api",
                              n_updates=30, weights=w_src)
        cst = CrossSessionTransfer()
        result = cst.select_and_blend([snap], "new", "api")
        assert result is not None

        for dim in V2_DIMENSIONS:
            d_transferred = abs(result["weights"][dim] - w_src[dim])
            d_default = abs(DEFAULT_WEIGHTS[dim] - w_src[dim])
            # Le poids transféré doit être plus proche de la source que le défaut
            assert d_transferred < d_default, (
                f"dim={dim}: transferred={result['weights'][dim]} "
                f"not closer to source={w_src[dim]} than default={DEFAULT_WEIGHTS[dim]}"
            )

    def test_session_decay_after_transfer_still_within_bounds(self):
        from hdwp.core.ml.models.feedback_loop import FeedbackLoop, WEIGHT_MIN, WEIGHT_MAX
        w_src = _uniform_weights(WEIGHT_MAX * 0.9)
        snap = _make_snapshot(n_updates=100, weights=w_src)
        cst = CrossSessionTransfer()
        result = cst.select_and_blend([snap], "new", "api")
        assert result is not None
        fl = FeedbackLoop()
        fl.load_serializable(result)
        fl.apply_session_decay()
        for w in fl.current_weights().values():
            assert WEIGHT_MIN <= w <= WEIGHT_MAX
