# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hdwp.server.models.state import LLMStatusResponse

router = APIRouter()

_ENV_MAP = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
_VALID_PROVIDERS = frozenset({"anthropic", "openai", "ollama"})
_LLM_CONFIG_PATH = Path.home() / ".hdwp" / "llm_config.json"


class LLMConfigRequest(BaseModel):
    enabled: bool
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"
    base_url: str | None = None


class ApiKeyRequest(BaseModel):
    provider: str
    api_key: str


@router.get("/llm/config", response_model=LLMStatusResponse)
async def get_llm_config(request: Request) -> LLMStatusResponse:
    session = request.app.state.server_state.get_active()
    config = session.context.config.llm if session else None

    # Fallback to global config if no session
    if config is None:
        llm = getattr(request.app.state, "llm_config", {}) or {}
        api_key_valid = bool(
            os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("HDWP_LLM_API_KEY")
        )
        return LLMStatusResponse(
            active=bool(llm.get("enabled", False)),
            provider=llm.get("provider"),
            model=llm.get("model"),
            api_key_valid=api_key_valid,
        )

    api_key_valid = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("HDWP_LLM_API_KEY")
    )
    return LLMStatusResponse(
        active=bool(config.enabled),
        provider=config.provider,
        model=config.model,
        api_key_valid=api_key_valid,
    )


@router.post("/llm/config")
async def set_llm_config(req: LLMConfigRequest, request: Request) -> dict:
    if req.provider not in _VALID_PROVIDERS:
        raise HTTPException(422, f"Provider invalide : {req.provider!r}. Valeurs acceptées : {sorted(_VALID_PROVIDERS)}")

    # Persist to disk
    cfg = {
        "enabled": req.enabled,
        "provider": req.provider,
        "model": req.model,
        "base_url": req.base_url,
    }
    _LLM_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LLM_CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    # Update in-memory global config
    request.app.state.llm_config = cfg

    # Apply to active session if present
    session = request.app.state.server_state.get_active()
    if session:
        from hdwp.core.context.config_schema import LLMConfig
        session.context.config.llm = LLMConfig(
            enabled=req.enabled,
            provider=req.provider,  # type: ignore[arg-type]
            model=req.model,
            base_url=req.base_url,
        )

    return {"ok": True}


@router.post("/llm/api-key")
async def save_api_key(req: ApiKeyRequest) -> dict:
    env_name = _ENV_MAP.get(req.provider)
    if not env_name:
        return {"ok": False, "error": "Provider invalide"}
    os.environ[env_name] = req.api_key
    _save_env_file(env_name, req.api_key)
    return {"ok": True}


@router.get("/llm/api-keys")
async def get_api_keys() -> dict:
    def _mask(key: str | None) -> str | None:
        if not key or len(key) < 8:
            return None
        return key[:7] + "..." + key[-4:]

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    return {
        "anthropic": {"set": bool(anthropic_key), "masked": _mask(anthropic_key), "required": True},
        "openai": {"set": bool(openai_key), "masked": _mask(openai_key), "required": True},
        "ollama": {"set": True, "masked": None, "required": False},
    }


def _save_env_file(env_name: str, value: str) -> None:
    env_path = Path.home() / ".hdwp" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines: dict[str, str] = {}
    if env_path.exists():
        for raw in env_path.read_text().splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k, v = stripped.split("=", 1)
                lines[k.strip()] = v.strip()

    lines[env_name] = value

    content = "# HDWP LLM API Keys — fichier genere automatiquement\n"
    for k, v in sorted(lines.items()):
        content += f"{k}={v}\n"

    env_path.write_text(content)
    env_path.chmod(0o600)
