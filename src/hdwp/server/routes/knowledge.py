# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from fastapi import APIRouter, Request

from hdwp.core.knowledge.base import BASE_WEIGHTS

router = APIRouter()


@router.get("/knowledge/stats")
async def get_knowledge_stats(request: Request) -> dict:
    kb = request.app.state.knowledge_base
    session_count = await kb.get_session_count()
    patterns = await kb.get_stats()
    return {"session_count": session_count, "patterns": patterns}


@router.get("/knowledge/learning-health")
async def get_learning_health(request: Request) -> dict:
    kb = request.app.state.knowledge_base
    patterns = await kb.get_stats()
    confidence_weights = await kb.get_confidence_weights()
    adapted_weights = await kb.get_adapted_weights()

    divergences: dict[str, dict] = {}
    for key, base in BASE_WEIGHTS.items():
        adapted = adapted_weights.get(key, base)
        div_pct = abs(adapted - base) / base * 100
        divergences[key] = {
            "base": base,
            "adapted": round(adapted, 4),
            "divergence_pct": round(div_pct, 1),
            "is_adapted": div_pct > 10,
        }

    return {
        "confidence_weights": confidence_weights,
        "adapted_weights": adapted_weights,
        "divergences": divergences,
        "patterns": patterns,
    }


@router.post("/knowledge/reset")
async def reset_knowledge(request: Request) -> dict:
    kb = request.app.state.knowledge_base
    await kb.reset()
    return {"ok": True}
