# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for dry-run mode: halts after HYPOTHESIZE, returns plan without running experiments."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hdwp.core.context.config_schema import HDWPContextConfig, OptionsConfig


def _make_hypothesis(
    hyp_id: str = "HYP-001",
    property_id: str = "prop-bola",
    priority: str = "HIGH",
    statement: str = "BOLA may be present",
    source_plugin: str = "bola_plugin",
    experiments: list | None = None,
) -> MagicMock:
    hyp = MagicMock()
    hyp.id = hyp_id
    hyp.property_id = property_id
    hyp.priority = priority
    hyp.statement = statement
    hyp.source_plugin = source_plugin
    hyp.required_experiments = experiments or []
    return hyp


def _make_experiment_spec(url: str = "https://example.com/api/users/1", mutation_type: str = "identity_swap") -> MagicMock:
    spec = MagicMock()
    spec.mutation_type = mutation_type
    spec.base_request = MagicMock()
    spec.base_request.url = url
    return spec


class TestBuildDryRunReport:
    """Unit tests for HDWPEngine._build_dry_run_report()."""

    def _make_engine(self) -> MagicMock:
        engine = MagicMock()
        engine._context = MagicMock()
        engine._context.base_url = "https://example.com"
        # Bind the real method
        from hdwp.core.engine import HDWPEngine
        engine._build_dry_run_report = HDWPEngine._build_dry_run_report.__get__(engine)
        return engine

    def test_empty_hypotheses_returns_valid_structure(self) -> None:
        engine = self._make_engine()
        result = engine._build_dry_run_report([])
        assert result["dry_run"] is True
        assert result["hypotheses_count"] == 0
        assert result["hypotheses"] == []
        assert result["no_requests_sent"] is True
        assert result["target"] == "https://example.com"

    def test_hypothesis_fields_present(self) -> None:
        spec = _make_experiment_spec("https://example.com/api/items/1", "identity_swap")
        hyp = _make_hypothesis(experiments=[spec])
        engine = self._make_engine()
        result = engine._build_dry_run_report([hyp])

        assert result["hypotheses_count"] == 1
        entry = result["hypotheses"][0]
        assert entry["id"] == "HYP-001"
        assert entry["property_id"] == "prop-bola"
        assert entry["priority"] == "HIGH"
        assert entry["statement"] == "BOLA may be present"
        assert entry["source_plugin"] == "bola_plugin"
        assert "https://example.com/api/items/1" in entry["affected_endpoints"]
        assert "identity_swap" in entry["planned_mutations"]
        assert entry["experiments_count"] == 1

    def test_hypotheses_sorted_by_priority(self) -> None:
        low = _make_hypothesis("HYP-LOW", priority="LOW")
        high = _make_hypothesis("HYP-HIGH", priority="HIGH")
        medium = _make_hypothesis("HYP-MED", priority="MEDIUM")
        engine = self._make_engine()
        result = engine._build_dry_run_report([low, medium, high])
        ids = [h["id"] for h in result["hypotheses"]]
        assert ids == ["HYP-HIGH", "HYP-MED", "HYP-LOW"]

    def test_endpoints_deduplicated(self) -> None:
        spec1 = _make_experiment_spec("https://example.com/api/users/1", "identity_swap")
        spec2 = _make_experiment_spec("https://example.com/api/users/1", "privilege_escalation")
        hyp = _make_hypothesis(experiments=[spec1, spec2])
        engine = self._make_engine()
        result = engine._build_dry_run_report([hyp])
        entry = result["hypotheses"][0]
        # Same URL should appear only once
        assert entry["affected_endpoints"].count("https://example.com/api/users/1") == 1


class TestOptionsConfigDryRun:
    """Verify dry_run field exists and defaults to False."""

    def test_dry_run_default_false(self) -> None:
        opts = OptionsConfig()
        assert opts.dry_run is False

    def test_dry_run_can_be_set_true(self) -> None:
        opts = OptionsConfig(dry_run=True)
        assert opts.dry_run is True

    def test_hdwp_context_config_has_dry_run(self) -> None:
        from hdwp.core.context.config_schema import (
            HDWPContextConfig,
            ScopeConfig,
            TargetConfig,
        )
        cfg = HDWPContextConfig(
            target=TargetConfig(base_url="https://example.com", name="test"),
            scope=ScopeConfig(include=["https://example.com"]),
        )
        assert cfg.options.dry_run is False
