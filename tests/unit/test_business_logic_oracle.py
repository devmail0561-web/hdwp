# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for business logic oracle (assess_business_boundary)."""
from __future__ import annotations

from datetime import UTC, datetime

from hdwp.core.model.schemas import (
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    generate_id,
)
from hdwp.core.oracle.injection_oracle import assess_business_boundary, assess_injection
from hdwp.core.oracle.violation_oracle import ViolationVerdict


def _make_experiment(status: int, body: object = None) -> ExperimentResult:
    return ExperimentResult(
        id=generate_id("EXP"),
        hypothesis_id="HYP-test",
        experiment_spec=ExperimentSpec(
            mutation_type="field_injection",
            base_request=NormalizedRequest(method="GET", url="http://test/api"),
            mutation_params={"payload_type": "boundary", "payload": "-1"},
        ),
        request_sent=NormalizedRequest(method="GET", url="http://test/api"),
        response_received=NormalizedResponse(
            status_code=status,
            body=body,
            headers={},
            content_type="application/json",
        ),
        timing_ms=50.0,
        timestamp=datetime.now(UTC).isoformat(),
    )


def test_400_response_is_refuted() -> None:
    exp = _make_experiment(400)
    result = assess_business_boundary("-1", exp)
    assert result.verdict == ViolationVerdict.REFUTED
    assert result.confidence_hint >= 0.8


def test_422_response_is_refuted() -> None:
    exp = _make_experiment(422)
    result = assess_business_boundary("-1", exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_200_with_negative_financial_field_is_confirmed() -> None:
    # Body as string containing negative financial value
    exp = _make_experiment(200, body='"total": -9.99')
    result = assess_business_boundary("-1", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.8


def test_200_with_payload_reflected_is_ambiguous() -> None:
    exp = _make_experiment(200, body={"result": "-1", "status": "ok"})
    result = assess_business_boundary("-1", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


def test_200_with_minus_9999_no_indicator_is_ambiguous() -> None:
    exp = _make_experiment(200, body={"message": "processed"})
    result = assess_business_boundary("-9999", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


def test_200_zero_payload_no_indicator_is_ambiguous() -> None:
    exp = _make_experiment(200, body={"message": "processed"})
    result = assess_business_boundary("0", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


def test_assess_injection_boundary_delegates_to_business_boundary() -> None:
    exp = _make_experiment(400)
    result = assess_injection("boundary", "-1", exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_assess_injection_sqli_unaffected_by_business() -> None:
    exp = _make_experiment(200, body={"data": "normal"})
    result = assess_injection("sqli", "' OR 1=1 --", exp)
    # No SQL error in body → REFUTED for sqli
    assert result.verdict == ViolationVerdict.REFUTED
