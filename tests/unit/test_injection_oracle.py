# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.model.schemas import (
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    generate_id,
)
from hdwp.core.oracle.injection_oracle import (
    assess_injection,
    assess_mass_assignment,
    assess_sqli,
    assess_ssti,
    assess_xss,
)
from hdwp.core.oracle.violation_oracle import ViolationVerdict


def _make_result(status: int, body: object = None, content_type: str = "application/json") -> ExperimentResult:
    spec = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url="http://test/"),
        mutation_params={"payload_type": "sqli", "payload": "'"},
    )
    return ExperimentResult(
        id=generate_id("EXP"),
        hypothesis_id="HYP-test",
        experiment_spec=spec,
        request_sent=NormalizedRequest(method="GET", url="http://test/"),
        response_received=NormalizedResponse(
            status_code=status,
            body=body,
            content_type=content_type,
        ),
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── SQLi ──────────────────────────────────────────────────────────────────

def test_sqli_confirmed_on_sql_error_in_body() -> None:
    exp = _make_result(200, "You have an error in your SQL syntax near '''")
    result = assess_sqli("'", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.9


def test_sqli_refuted_on_normal_response() -> None:
    exp = _make_result(200, {"results": [], "query": "test"})
    result = assess_sqli("'", exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_sqli_confirmed_on_500_with_stack_trace() -> None:
    exp = _make_result(500, 'Traceback (most recent call last):\n  File "app.py", line 42')
    result = assess_sqli("'", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.7


def test_sqli_ambiguous_on_500_without_trace() -> None:
    exp = _make_result(500, "Internal Server Error")
    result = assess_sqli("'", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


def test_sqli_confirmed_on_oracle_error() -> None:
    exp = _make_result(200, "ORA-00942: table or view does not exist")
    result = assess_sqli("'", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED


# ── XSS ───────────────────────────────────────────────────────────────────

def test_xss_confirmed_payload_reflected_in_html() -> None:
    payload = "<script>alert(1)</script>"
    exp = _make_result(200, f"<h1>Hello, {payload}!</h1>", content_type="text/html")
    result = assess_xss(payload, exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.9


def test_xss_refuted_payload_html_encoded() -> None:
    payload = "<script>alert(1)</script>"
    exp = _make_result(200, "&lt;script&gt;alert(1)&lt;/script&gt;", content_type="text/html")
    result = assess_xss(payload, exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_xss_refuted_payload_not_reflected() -> None:
    payload = "<script>alert(1)</script>"
    exp = _make_result(200, "<h1>Hello, World!</h1>", content_type="text/html")
    result = assess_xss(payload, exp)
    assert result.verdict == ViolationVerdict.REFUTED


# ── SSTI ──────────────────────────────────────────────────────────────────

def test_ssti_confirmed_template_evaluated() -> None:
    exp = _make_result(200, "Result: 49", content_type="text/html")
    result = assess_ssti("{{7*7}}", "49", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.95


def test_ssti_refuted_payload_reflected_as_is() -> None:
    exp = _make_result(200, "Result: {{7*7}}", content_type="text/html")
    result = assess_ssti("{{7*7}}", "49", exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_ssti_insufficient_when_neither() -> None:
    exp = _make_result(200, "Result: something else", content_type="text/html")
    result = assess_ssti("{{7*7}}", "49", exp)
    assert result.verdict == ViolationVerdict.INSUFFICIENT


# ── Mass assignment ───────────────────────────────────────────────────────

def test_mass_assign_confirmed_field_in_response() -> None:
    exp = _make_result(200, {"id": 1, "name": "Alice", "is_admin": True})
    result = assess_mass_assignment("is_admin", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.85


def test_mass_assign_refuted_on_4xx() -> None:
    exp = _make_result(400, {"error": "bad request"})
    result = assess_mass_assignment("is_admin", exp)
    assert result.verdict == ViolationVerdict.REFUTED


def test_mass_assign_ambiguous_field_accepted_but_not_in_response() -> None:
    exp = _make_result(200, {"id": 1, "name": "Alice"})
    result = assess_mass_assignment("is_admin", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


# ── Unified assess_injection ──────────────────────────────────────────────

def test_assess_injection_unknown_type_returns_insufficient() -> None:
    exp = _make_result(200, "ok")
    result = assess_injection("unknown_type", "payload", exp)
    assert result.verdict == ViolationVerdict.INSUFFICIENT
