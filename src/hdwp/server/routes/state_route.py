# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import os

from fastapi import APIRouter, Request

from hdwp.server.models.state import LLMStatusResponse, StateResponse

router = APIRouter()


@router.get("/state", response_model=StateResponse)
async def get_state(request: Request) -> StateResponse:
    session = request.app.state.server_state.get_active()
    if not session:
        return StateResponse(status="idle")

    endpoint_count = 0
    hypothesis_count = 0
    model_confidence = 0.0
    property_count = 0
    experiment_count = 0
    tech_stack: list[str] = []
    detected_versions: dict[str, str] = {}
    detected_content_types: list[str] = []
    threat_score_max = 0.0
    invariant_violation_count = 0
    invariant_count = 0
    waf_detected = False
    if session.engine:
        try:
            snap = session.engine._app_model.snapshot()
            endpoint_count = len(snap.endpoints)
            hypothesis_count = len(session.engine._hyp_engine.hypotheses)
            model_confidence = session.engine._app_model.model_confidence
            if session.engine._prop_engine:
                property_count = len(session.engine._prop_engine.properties)
            experiment_count = len(session.engine._exp_engine._results_buffer)
            tech_stack = snap.tech_stack
            detected_versions = snap.detected_versions
            detected_content_types = snap.detected_content_types
        except Exception:
            pass
        try:
            if getattr(session.engine, "_threat_engine", None) is not None:
                scores = session.engine._threat_engine.scores
                if scores:
                    threat_score_max = max(scores.values())
            if getattr(session.engine, "_invariant_store", None) is not None:
                all_invs = session.engine._invariant_store.all_invariants()
                invariant_count = len(all_invs)
                invariant_violation_count = sum(inv.violation_count for inv in all_invs)
            if getattr(session.engine, "_adaptive_payload_engine", None) is not None:
                waf_detected = bool(session.engine._adaptive_payload_engine.detected_wafs)
        except Exception:
            pass

    return StateResponse(
        status=session.status,
        session_id=session.session_id,
        target_url=session.target_url,
        phase=session.phase,
        model_confidence=model_confidence,
        endpoint_count=endpoint_count,
        hypothesis_count=hypothesis_count,
        findings_count=session.findings_count,
        property_count=property_count,
        experiment_count=experiment_count,
        proxy_active=session.proxy_active,
        error_message=session.error_message,
        tech_stack=tech_stack,
        detected_versions=detected_versions,
        detected_content_types=detected_content_types,
        threat_score_max=threat_score_max,
        invariant_violation_count=invariant_violation_count,
        invariant_count=invariant_count,
        waf_detected=waf_detected,
    )


@router.get("/llm/status", response_model=LLMStatusResponse)
async def llm_status(request: Request) -> LLMStatusResponse:
    session = request.app.state.server_state.get_active()
    config = session.context.config.llm if session else None
    api_key_valid = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("HDWP_LLM_API_KEY")
    )
    return LLMStatusResponse(
        active=bool(config and config.enabled),
        provider=config.provider if config else None,
        model=config.model if config else None,
        api_key_valid=api_key_valid,
    )
