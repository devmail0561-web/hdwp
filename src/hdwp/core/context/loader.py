# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from hdwp.core.context.config_schema import HDWPContextConfig

ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)}")


class EngineContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    config: HDWPContextConfig
    base_url: str
    session_id: str


class ContextLoaderError(Exception):
    pass


class ContextLoader:
    @classmethod
    def load(cls, path: Path) -> EngineContext:
        if not path.exists():
            raise ContextLoaderError(f"Context file not found: {path}")

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ContextLoaderError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ContextLoaderError(f"Context file must be a YAML mapping, got {type(raw).__name__}")

        cls._resolve_env_vars(raw, path)

        try:
            config = HDWPContextConfig.model_validate(raw)
        except Exception as exc:
            raise ContextLoaderError(f"Validation error in {path}: {exc}") from exc

        return EngineContext(
            config=config,
            base_url=config.target.base_url,
            session_id=f"SESSION-{uuid.uuid4().hex[:8]}",
        )

    @classmethod
    def _resolve_env_vars(cls, obj: object, path: Path) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    obj[key] = cls._replace_env_vars(value, path)
                else:
                    cls._resolve_env_vars(value, path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = cls._replace_env_vars(item, path)
                else:
                    cls._resolve_env_vars(item, path)

    @classmethod
    def _replace_env_vars(cls, value: str, path: Path) -> str:
        def replacer(match: re.Match[str]) -> str:
            var_name = match.group(1)
            env_value = os.environ.get(var_name)
            if env_value is None:
                raise ContextLoaderError(
                    f"Environment variable '{var_name}' referenced in {path} is not set"
                )
            return env_value

        return ENV_VAR_PATTERN.sub(replacer, value)
