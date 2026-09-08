# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDING_CONFIRMED
from hdwp.core.model.schemas import (
    ConfidenceScore,
    Finding,
    FindingExplanation,
    SignalContribution,
    generate_id,
)
from hdwp.core.oracle.confidence import (
    ConfidenceModelV2,
    V2_DEFAULT_WEIGHTS,
    V2_DIMENSIONS,
    _DIMENSION_LABELS,
)
from hdwp.core.report.json_export import compute_summary
from hdwp.core.report.markdown import render_markdown


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_features(**overrides: float) -> dict[str, float]:
    base = {dim: 0.0 for dim in V2_DIMENSIONS}
    base.update(overrides)
    return base


def _make_explanation(
    v1: float = 0.7,
    v2: float = 0.85,
    ml: float = 0.0,
    **signal_overrides: float,
) -> FindingExplanation:
    signals = _make_features(**signal_overrides)
    model = ConfidenceModelV2()
    top = model.explain(signals)
    active = [c for c in top if abs(c.contribution) > 0.01]
    rationale = "Test rationale"
    return FindingExplanation(
        v1_score=v1,
        v2_score=v2,
        ml_score=ml,
        signals=signals,
        top_contributors=active[:5],
        verdict_rationale=rationale,
    )


def _make_finding(
    severity: str = "HIGH",
    explanation: FindingExplanation | None = None,
) -> Finding:
    return Finding(
        id=generate_id("FIND"),
        hypothesis_id=generate_id("HYP"),
        property_id=generate_id("PROP"),
        status="CONFIRMED",
        confidence=0.92,
        confidence_breakdown=ConfidenceScore(overall=0.92, v2_boost=0.05, ml_boost=0.02),
        explanation=explanation,
        owasp_category="A01:2021",
        cwe_id="CWE-639",
        severity=severity,
        affected_endpoints=["/api/users/1"],
        proof={
            "experiments": ["EXP-001"],
            "diffs": ["DIFF-001"],
            "reproduction_steps": ["1. GET /api/users/1"],
        },
        remediation_hint="Vérifier l'ownership côté serveur.",
    )


# ── ConfidenceModelV2.explain() ─────────────────────────────────────────────


class TestExplainMethod:
    def test_returns_all_ten_dimensions(self) -> None:
        model = ConfidenceModelV2()
        features = _make_features(oracle_strength=0.8, reproducibility=0.7)
        result = model.explain(features)
        assert len(result) == 10
        dims = {c.dimension for c in result}
        assert dims == set(V2_DIMENSIONS)

    def test_sorted_by_absolute_contribution_descending(self) -> None:
        model = ConfidenceModelV2()
        features = _make_features(
            oracle_strength=0.5,
            reproducibility=0.9,
            invariant_violated=1.0,
        )
        result = model.explain(features)
        contribs = [abs(c.contribution) for c in result]
        assert contribs == sorted(contribs, reverse=True)

    def test_contribution_equals_weight_times_value(self) -> None:
        model = ConfidenceModelV2()
        features = _make_features(oracle_strength=0.6, temporal_signal=0.8)
        result = model.explain(features)
        for c in result:
            expected = round(c.weight * c.raw_value, 4)
            assert c.contribution == expected

    def test_zero_features_give_zero_contributions(self) -> None:
        model = ConfidenceModelV2()
        result = model.explain(_make_features())
        for c in result:
            assert c.contribution == 0.0

    def test_labels_populated_from_dimension_labels(self) -> None:
        model = ConfidenceModelV2()
        result = model.explain(_make_features(invariant_violated=1.0))
        by_dim = {c.dimension: c for c in result}
        assert by_dim["invariant_violated"].label == "Invariant de sécurité violé"
        assert by_dim["reproducibility"].label == "Reproductibilité"

    def test_all_dimensions_have_labels(self) -> None:
        for dim in V2_DIMENSIONS:
            assert dim in _DIMENSION_LABELS

    def test_invariant_violated_is_top_contributor(self) -> None:
        model = ConfidenceModelV2()
        features = _make_features(
            oracle_strength=0.5,
            reproducibility=0.5,
            invariant_violated=1.0,
        )
        result = model.explain(features)
        assert result[0].dimension == "invariant_violated"

    def test_custom_weights_reflected_in_explain(self) -> None:
        model = ConfidenceModelV2()
        model.update_weights({"temporal_signal": 10.0})
        features = _make_features(temporal_signal=0.5)
        result = model.explain(features)
        by_dim = {c.dimension: c for c in result}
        assert by_dim["temporal_signal"].weight == 10.0
        assert by_dim["temporal_signal"].contribution == 5.0


# ── FindingExplanation schema ────────────────────────────────────────────────


class TestFindingExplanationSchema:
    def test_roundtrip_serialization(self) -> None:
        ex = _make_explanation(
            v1=0.7, v2=0.85,
            oracle_strength=0.8, reproducibility=0.7, invariant_violated=1.0,
        )
        data = ex.model_dump()
        restored = FindingExplanation.model_validate(data)
        assert restored.v1_score == ex.v1_score
        assert restored.v2_score == ex.v2_score
        assert len(restored.top_contributors) == len(ex.top_contributors)

    def test_finding_with_explanation_serializes(self) -> None:
        ex = _make_explanation(oracle_strength=0.9)
        f = _make_finding(explanation=ex)
        data = f.model_dump()
        assert data["explanation"] is not None
        assert data["explanation"]["v1_score"] == ex.v1_score

    def test_finding_without_explanation_serializes(self) -> None:
        f = _make_finding(explanation=None)
        data = f.model_dump()
        assert data["explanation"] is None

    def test_finding_with_explanation_validates_from_dict(self) -> None:
        ex = _make_explanation(crossrole_signal=0.9)
        f = _make_finding(explanation=ex)
        data = f.model_dump()
        restored = Finding.model_validate(data)
        assert restored.explanation is not None
        assert restored.explanation.v2_score == ex.v2_score


# ── Markdown report rendering ────────────────────────────────────────────────


class TestMarkdownExplanation:
    def test_explanation_rendered_in_markdown(self) -> None:
        ex = _make_explanation(
            oracle_strength=0.8, reproducibility=0.7, invariant_violated=1.0,
        )
        f = _make_finding(explanation=ex)
        md = render_markdown([f])
        assert "Analyse de confiance" in md
        assert "V1 (5D linéaire)" in md
        assert "V2 (10D logistique)" in md

    def test_top_contributors_table_in_markdown(self) -> None:
        ex = _make_explanation(
            oracle_strength=0.8, invariant_violated=1.0,
        )
        f = _make_finding(explanation=ex)
        md = render_markdown([f])
        assert "Invariant de sécurité violé" in md
        assert "Signal" in md
        assert "Contribution" in md

    def test_verdict_rationale_in_markdown(self) -> None:
        ex = _make_explanation(oracle_strength=0.5)
        f = _make_finding(explanation=ex)
        md = render_markdown([f])
        assert "Test rationale" in md

    def test_no_explanation_no_crash(self) -> None:
        f = _make_finding(explanation=None)
        md = render_markdown([f])
        assert "Analyse de confiance" not in md
        assert f.id in md

    def test_ml_score_shown_when_nonzero(self) -> None:
        ex = _make_explanation(v1=0.7, v2=0.85, ml=0.90, oracle_strength=0.8)
        f = _make_finding(explanation=ex)
        md = render_markdown([f])
        assert "OracleModel MLP" in md

    def test_ml_score_hidden_when_zero(self) -> None:
        ex = _make_explanation(v1=0.7, v2=0.85, ml=0.0, oracle_strength=0.8)
        f = _make_finding(explanation=ex)
        md = render_markdown([f])
        assert "OracleModel MLP" not in md


# ── JSON export ──────────────────────────────────────────────────────────────


class TestJsonExportExplanation:
    def test_summary_includes_explained_count(self) -> None:
        ex = _make_explanation(oracle_strength=0.8, invariant_violated=1.0)
        findings = [
            _make_finding(explanation=ex),
            _make_finding(explanation=None),
        ]
        summary = compute_summary(findings)
        assert summary["explained_count"] == 1

    def test_summary_top_contributing_signals(self) -> None:
        ex = _make_explanation(oracle_strength=0.8, invariant_violated=1.0)
        findings = [_make_finding(explanation=ex)]
        summary = compute_summary(findings)
        assert "top_contributing_signals" in summary
        assert "invariant_violated" in summary["top_contributing_signals"]

    def test_summary_no_findings_explained_count_zero(self) -> None:
        summary = compute_summary([])
        assert summary["explained_count"] == 0
        assert summary["top_contributing_signals"] == {}

    def test_finding_json_includes_explanation(self) -> None:
        ex = _make_explanation(crossrole_signal=0.9)
        f = _make_finding(explanation=ex)
        data = json.loads(json.dumps(f.model_dump()))
        assert data["explanation"]["signals"]["crossrole_signal"] == 0.9
        assert len(data["explanation"]["top_contributors"]) > 0
