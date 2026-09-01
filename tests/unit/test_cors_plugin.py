# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    ExperimentResult,
    SemanticDiff,
    DiffVerdict,
    generate_id,
)
from hdwp.core.oracle.violation_oracle import (
    ViolationVerdict,
    assess_violation,
)
from hdwp.plugins.core.configuration.cors import CORSPlugin, EVIL_ORIGIN


def _make_model_with_endpoints(n: int = 3) -> ApplicationModelData:
    endpoints = [
        EndpointNode(id=generate_id("EP"), path=f"/api/resource{i}", methods=["GET"])
        for i in range(n)
    ]
    return ApplicationModelData(endpoints=endpoints)


def _empty_model() -> ApplicationModelData:
    return ApplicationModelData()


def _make_experiment(acao: str | None, mutation_params: dict | None = None) -> ExperimentResult:
    headers = {}
    if acao is not None:
        headers["access-control-allow-origin"] = acao
    return ExperimentResult(
        hypothesis_id="HYP-x",
        experiment_spec=ExperimentSpec(
            mutation_type="origin_test",
            base_request=NormalizedRequest(method="GET", url="http://x"),
            mutation_params=mutation_params or {"evil_origin": EVIL_ORIGIN},
        ),
        request_sent=NormalizedRequest(method="GET", url="http://x"),
        response_received=NormalizedResponse(status_code=200, headers=headers),
        timing_ms=1.0,
        timestamp="2026-01-01T00:00:00Z",
    )


def _make_baseline() -> ExperimentResult:
    return ExperimentResult(
        hypothesis_id="HYP-x",
        experiment_spec=ExperimentSpec(
            mutation_type="origin_test",
            base_request=NormalizedRequest(method="GET", url="http://x"),
            mutation_params={"evil_origin": EVIL_ORIGIN},
        ),
        request_sent=NormalizedRequest(method="GET", url="http://x"),
        response_received=NormalizedResponse(status_code=200),
        timing_ms=1.0,
        timestamp="2026-01-01T00:00:00Z",
    )


def _make_diff() -> SemanticDiff:
    return SemanticDiff(
        id=generate_id("DIFF"),
        exp_a="a",
        exp_b="b",
        verdict=DiffVerdict.INSIGNIFICANT,
        verdict_rationale="",
    )


def test_no_properties_empty_model():
    plugin = CORSPlugin()
    assert plugin.infer_properties(_empty_model()) == []


def test_properties_with_endpoints():
    plugin = CORSPlugin()
    model = _make_model_with_endpoints(3)
    props = plugin.infer_properties(model)
    assert len(props) == 1
    assert "CORS" in props[0].formal_statement


def test_hypotheses_generated_for_endpoints():
    plugin = CORSPlugin()
    model = _make_model_with_endpoints(3)
    hyps = plugin.generate_hypotheses(model)
    assert len(hyps) == 3
    for h in hyps:
        assert h.required_experiments[0].mutation_type == "origin_test"
        assert h.required_experiments[0].mutation_params["evil_origin"] == EVIL_ORIGIN


def test_hypotheses_max_five_endpoints():
    plugin = CORSPlugin()
    model = _make_model_with_endpoints(10)
    hyps = plugin.generate_hypotheses(model)
    assert len(hyps) == 5


def test_assess_cors_wildcard_confirmed():
    baseline = _make_baseline()
    experiment = _make_experiment("*")
    diff = _make_diff()
    result = assess_violation("origin_test", baseline, experiment, diff)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert "*" in result.rationale


def test_assess_cors_evil_origin_reflected_confirmed():
    baseline = _make_baseline()
    experiment = _make_experiment(
        EVIL_ORIGIN,
        mutation_params={"evil_origin": EVIL_ORIGIN},
    )
    diff = _make_diff()
    result = assess_violation("origin_test", baseline, experiment, diff)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert "reflète" in result.rationale


def test_assess_cors_no_header_refuted():
    baseline = _make_baseline()
    experiment = _make_experiment(None)
    diff = _make_diff()
    result = assess_violation("origin_test", baseline, experiment, diff)
    assert result.verdict == ViolationVerdict.REFUTED


def test_assess_cors_restricted_origin_refuted():
    baseline = _make_baseline()
    experiment = _make_experiment("https://trusted.example.com")
    diff = _make_diff()
    result = assess_violation("origin_test", baseline, experiment, diff)
    assert result.verdict == ViolationVerdict.REFUTED
