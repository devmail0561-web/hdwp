# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for Phase 7 LLM layer extensions."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from hdwp.core.llm.layer import AnthropicLLMLayer
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConfidenceScore,
    EndpointNode,
    Finding,
    ParameterNode,
    RoleNode,
)
from hdwp.core.oracle.violation_oracle import ViolationVerdict


def _make_finding(
    remediation_hint: str = "Fix it.",
    severity: str = "HIGH",
) -> Finding:
    return Finding(
        hypothesis_id="HYP-test",
        property_id="PROP-test",
        status="CONFIRMED",
        confidence=0.9,
        confidence_breakdown=ConfidenceScore(overall=0.9),
        owasp_category="A01:2021",
        cwe_id="CWE-639",
        severity=severity,
        affected_endpoints=["/api/users/1"],
        proof={"reproduction_steps": ["Step 1"], "experiments": [], "diffs": []},
        remediation_hint=remediation_hint,
    )


def _make_layer() -> AnthropicLLMLayer:
    """Build a layer with a mocked Anthropic client."""
    layer = AnthropicLLMLayer.__new__(AnthropicLLMLayer)
    layer._model = "test-model"
    layer._client = MagicMock()
    return layer


def _mock_response(text: str) -> MagicMock:
    msg = MagicMock()
    msg.content = [MagicMock(text=text)]
    return msg


# ── generate_remediation_hint ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_remediation_hint_success() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(
        return_value=_mock_response("Vérifier l'ownership côté serveur.")
    )
    finding = _make_finding(remediation_hint="Old hint.")
    result = await layer.generate_remediation_hint(finding)
    assert result == "Vérifier l'ownership côté serveur."


@pytest.mark.asyncio
async def test_generate_remediation_hint_fallback() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
    finding = _make_finding(remediation_hint="Original hint.")
    result = await layer.generate_remediation_hint(finding)
    # Falls back to the existing hint
    assert result == "Original hint."


# ── generate_executive_summary ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_executive_summary_success() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(
        return_value=_mock_response("L'application présente des risques critiques.")
    )
    findings = [_make_finding()]
    result = await layer.generate_executive_summary(findings, "target.example.com")
    assert "critiques" in result.lower()


@pytest.mark.asyncio
async def test_generate_executive_summary_fallback() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
    findings = [_make_finding(severity="HIGH"), _make_finding(severity="MEDIUM")]
    result = await layer.generate_executive_summary(findings, "target")
    # Statistical fallback
    assert "2" in result
    assert "target" in result


@pytest.mark.asyncio
async def test_generate_executive_summary_empty_findings() -> None:
    layer = _make_layer()
    # Should not even call the API for 0 findings
    layer._client.messages.create = AsyncMock()
    result = await layer.generate_executive_summary([], "target")
    assert "aucun" in result.lower()
    layer._client.messages.create.assert_not_called()


# ── interpret_js ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_interpret_js_parses_json_response() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(
        return_value=_mock_response('["/api/users", "/api/orders/{id}"]')
    )
    result = await layer.interpret_js("var r='/api/users';")
    assert "/api/users" in result
    assert "/api/orders/{id}" in result


@pytest.mark.asyncio
async def test_interpret_js_parses_json_embedded_in_text() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(
        return_value=_mock_response('Here are the endpoints: ["/api/login"]\nDone.')
    )
    result = await layer.interpret_js("/* obfuscated */")
    assert "/api/login" in result


@pytest.mark.asyncio
async def test_interpret_js_fallback() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
    result = await layer.interpret_js("code")
    assert result == []


# ── propose_hypotheses ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_propose_hypotheses_success() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(
        return_value=_mock_response(
            "Il est possible que le paramètre 'amount' soit vulnérable.\n"
            "Il est possible qu'un race condition existe sur /api/pay.\n"
            "Il est possible que le champ 'role' soit mass-assignable."
        )
    )
    model = ApplicationModelData(
        endpoints=[EndpointNode(path="/api/pay", methods=["POST"])],
        parameters=[ParameterNode(name="amount", location="body", type_inferred="integer")],
        roles=[RoleNode(name="user_a"), RoleNode(name="user_b")],
    )
    result = await layer.propose_hypotheses(model, existing_count=3)
    assert len(result) <= 3
    assert all(h.startswith("Il est possible") for h in result)


@pytest.mark.asyncio
async def test_propose_hypotheses_fallback() -> None:
    layer = _make_layer()
    layer._client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
    model = ApplicationModelData()
    result = await layer.propose_hypotheses(model, existing_count=0)
    assert result == []


# ── ADR-002 invariant ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_disambiguate_diff_never_returns_confirmed() -> None:
    """Verify the LLM cannot trigger CONFIRMED status via disambiguation."""
    from hdwp.core.llm.layer import _parse_llm_verdict
    for text in ["violation", "VIOLATION", "Violation détectée", "oui violation", "vraie violation"]:
        result = _parse_llm_verdict(text.lower())
        assert result.verdict != ViolationVerdict.CONFIRMED, (
            f"_parse_llm_verdict returned CONFIRMED for '{text}' — violates ADR-002"
        )
