# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
)
from hdwp.core.experiment.temporal_module import assess_race_condition
from hdwp.plugins.core.business_invariant.race_condition import RaceConditionPlugin


def _make_model(**kwargs) -> ApplicationModelData:
    defaults = dict(endpoints=[], parameters=[], objects=[], roles=[], relations=[])
    defaults.update(kwargs)
    return ApplicationModelData(**defaults)


def _make_exp(status: int, body: object = None) -> ExperimentResult:
    spec = ExperimentSpec(
        mutation_type="race_condition",
        base_request=NormalizedRequest(method="POST", url="http://t/"),
        mutation_params={},
    )
    return ExperimentResult(
        hypothesis_id="HYP-test",
        experiment_spec=spec,
        request_sent=NormalizedRequest(method="POST", url="http://t/"),
        response_received=NormalizedResponse(status_code=status, body=body, timing_ms=50.0),
        timing_ms=50.0,
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── RaceConditionPlugin ───────────────────────────────────────────────────────

def test_payment_endpoint_generates_hypothesis() -> None:
    ep = EndpointNode(path="/api/payment", methods=["POST"])
    model = _make_model(endpoints=[ep])
    hyps = RaceConditionPlugin().generate_hypotheses(model)
    assert len(hyps) == 1
    assert "payment" in hyps[0].statement
    assert hyps[0].required_experiments[0].mutation_type == "race_condition"


def test_profile_get_no_hypothesis() -> None:
    ep = EndpointNode(path="/api/profile", methods=["GET"])
    model = _make_model(endpoints=[ep])
    assert RaceConditionPlugin().generate_hypotheses(model) == []


def test_order_post_generates_property() -> None:
    ep = EndpointNode(path="/api/order", methods=["POST"])
    model = _make_model(endpoints=[ep])
    props = RaceConditionPlugin().infer_properties(model)
    assert len(props) == 1
    assert "order" in props[0].formal_statement


def test_no_race_endpoints_no_properties() -> None:
    ep = EndpointNode(path="/api/users", methods=["GET"])
    model = _make_model(endpoints=[ep])
    assert RaceConditionPlugin().infer_properties(model) == []


# ── assess_race_condition ─────────────────────────────────────────────────────

def test_inconsistent_statuses_suspicious() -> None:
    results = [_make_exp(200), _make_exp(409), _make_exp(200)]
    assessment = assess_race_condition(results)
    assert assessment["suspicious"] is True


def test_consistent_statuses_not_suspicious() -> None:
    results = [_make_exp(200, {"balance": 100})] * 5
    assessment = assess_race_condition(results)
    assert assessment["suspicious"] is False


def test_negative_value_suspicious() -> None:
    results = [_make_exp(200, {"balance": -5})]
    assessment = assess_race_condition(results)
    assert assessment["suspicious"] is True
