# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest
import respx
import httpx

from hdwp.core.experiment.temporal_module import TemporalModule, assess_race_condition
from hdwp.core.model.schemas import ExperimentResult, ExperimentSpec, NormalizedRequest


def _make_spec(mutation_type: str = "race_condition") -> ExperimentSpec:
    return ExperimentSpec(
        mutation_type=mutation_type,
        base_request=NormalizedRequest(method="GET", url="http://test.local/api/resource"),
        mutation_params={},
        description="test",
    )


def _make_request() -> NormalizedRequest:
    return NormalizedRequest(
        method="GET",
        url="http://test.local/api/resource",
        headers={"Authorization": "Bearer token123"},
    )


@pytest.mark.asyncio
async def test_race_condition_emits_n_results():
    spec = _make_spec()
    req = _make_request()
    module = TemporalModule()

    with respx.mock:
        respx.get("http://test.local/api/resource").mock(
            return_value=httpx.Response(200, json={"count": 10})
        )
        async with httpx.AsyncClient() as client:
            results = await module.run_race_condition(
                client, req, "HYP-test", spec, concurrency=5
            )

    assert len(results) == 5
    for r in results:
        assert r.hypothesis_id == "HYP-test"


@pytest.mark.asyncio
async def test_race_condition_handles_errors_gracefully():
    spec = _make_spec()
    req = _make_request()
    module = TemporalModule()

    with respx.mock:
        respx.get("http://test.local/api/resource").mock(side_effect=httpx.ConnectError("fail"))
        async with httpx.AsyncClient() as client:
            results = await module.run_race_condition(
                client, req, "HYP-test", spec, concurrency=3
            )

    assert len(results) == 3
    for r in results:
        assert r.response_received.status_code == 0


def test_assess_race_condition_suspicious_on_mixed_statuses():
    def _result(status: int) -> ExperimentResult:
        return ExperimentResult(
            hypothesis_id="HYP-x",
            experiment_spec=ExperimentSpec(
                mutation_type="race_condition",
                base_request=NormalizedRequest(method="GET", url="http://x"),
                mutation_params={},
            ),
            request_sent=NormalizedRequest(method="GET", url="http://x"),
            response_received=__import__("hdwp.core.model.schemas", fromlist=["NormalizedResponse"]).NormalizedResponse(
                status_code=status
            ),
            timing_ms=1.0,
            timestamp="2026-01-01T00:00:00Z",
        )

    results = [_result(200), _result(200), _result(409)]
    assessment = assess_race_condition(results)
    assert assessment["suspicious"] is True
    assert "409" in assessment["rationale"]


def test_assess_race_condition_not_suspicious_on_uniform_statuses():
    from hdwp.core.model.schemas import NormalizedResponse

    def _result() -> ExperimentResult:
        return ExperimentResult(
            hypothesis_id="HYP-x",
            experiment_spec=ExperimentSpec(
                mutation_type="race_condition",
                base_request=NormalizedRequest(method="GET", url="http://x"),
                mutation_params={},
            ),
            request_sent=NormalizedRequest(method="GET", url="http://x"),
            response_received=NormalizedResponse(status_code=200, body={"count": 5}),
            timing_ms=1.0,
            timestamp="2026-01-01T00:00:00Z",
        )

    assessment = assess_race_condition([_result() for _ in range(5)])
    assert assessment["suspicious"] is False


def test_assess_race_condition_suspicious_on_negative_value():
    from hdwp.core.model.schemas import NormalizedResponse

    def _result(balance: int) -> ExperimentResult:
        return ExperimentResult(
            hypothesis_id="HYP-x",
            experiment_spec=ExperimentSpec(
                mutation_type="race_condition",
                base_request=NormalizedRequest(method="GET", url="http://x"),
                mutation_params={},
            ),
            request_sent=NormalizedRequest(method="GET", url="http://x"),
            response_received=NormalizedResponse(status_code=200, body={"balance": balance}),
            timing_ms=1.0,
            timestamp="2026-01-01T00:00:00Z",
        )

    # One result has negative balance → race condition
    results = [_result(10), _result(-5), _result(10)]
    assessment = assess_race_condition(results)
    assert assessment["suspicious"] is True


@pytest.mark.asyncio
async def test_token_reuse_returns_two_results():
    spec = _make_spec("token_reuse")
    req = _make_request()
    module = TemporalModule()

    with respx.mock:
        respx.get("http://test.local/api/resource").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        async with httpx.AsyncClient() as client:
            results = await module.run_token_reuse(
                client, req, None, "HYP-test", spec
            )

    assert len(results) == 2
    assert results[1].replayed_from == results[0].id
