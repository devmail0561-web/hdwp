# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()

_TIMEOUT = 5.0

_ANTHROPIC_FALLBACK = [
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-opus-4",
]

_OPENAI_FALLBACK = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4.1",
    "gpt-4.1-mini",
    "o3",
    "o4-mini",
]

_OPENAI_PREFIXES = ("gpt-4", "gpt-3.5", "o1", "o3", "o4", "chatgpt")


class ModelsResponse(BaseModel):
    models: list[str]
    error: str | None = None


@router.get("/llm/models", response_model=ModelsResponse)
async def list_models(provider: str, request: Request) -> ModelsResponse:
    if provider == "anthropic":
        return await _fetch_anthropic()
    if provider == "openai":
        return await _fetch_openai()
    if provider == "ollama":
        base_url = _get_ollama_base_url(request)
        return await _fetch_ollama(base_url)
    return ModelsResponse(models=[], error=f"Provider inconnu : {provider}")


async def _fetch_anthropic() -> ModelsResponse:
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("HDWP_LLM_API_KEY")
    if not key:
        return ModelsResponse(models=_ANTHROPIC_FALLBACK, error="Clé API requise — liste par défaut")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            )
            resp.raise_for_status()
            data = resp.json()
            models = sorted(
                m["id"] for m in data.get("data", [])
                if isinstance(m, dict) and str(m.get("id", "")).startswith("claude")
            )
            return ModelsResponse(models=models if models else _ANTHROPIC_FALLBACK)
    except Exception as exc:
        return ModelsResponse(models=_ANTHROPIC_FALLBACK, error=str(exc))


async def _fetch_openai() -> ModelsResponse:
    key = os.environ.get("OPENAI_API_KEY") or os.environ.get("HDWP_LLM_API_KEY")
    if not key:
        return ModelsResponse(models=_OPENAI_FALLBACK, error="Clé API requise — liste par défaut")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            resp.raise_for_status()
            data = resp.json()
            models = sorted(
                m["id"] for m in data.get("data", [])
                if isinstance(m, dict) and str(m.get("id", "")).startswith(_OPENAI_PREFIXES)
            )
            return ModelsResponse(models=models if models else _OPENAI_FALLBACK)
    except Exception as exc:
        return ModelsResponse(models=_OPENAI_FALLBACK, error=str(exc))


async def _fetch_ollama(base_url: str) -> ModelsResponse:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [
                m["name"] for m in data.get("models", [])
                if isinstance(m, dict) and m.get("name")
            ]
            return ModelsResponse(models=sorted(models))
    except Exception as exc:
        return ModelsResponse(models=[], error=str(exc))


def _get_ollama_base_url(request: Request) -> str:
    session = request.app.state.server_state.get_active()
    if session and session.context and session.context.config.llm.base_url:
        url = session.context.config.llm.base_url.rstrip("/")
        if url.endswith("/v1"):
            url = url[:-3]
        return url
    return "http://localhost:11434"
