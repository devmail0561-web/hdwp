# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator


class ManualToken(BaseModel):
    role_name: str
    token_type: Literal["bearer", "basic", "api_key", "cookie"] = "bearer"
    token_value: str
    username: str | None = None
    password: str | None = None


class NewSessionRequest(BaseModel):
    target_url: str
    mode: Literal["auto", "yaml", "manual"] = "auto"
    yaml_path: str | None = None
    manual_tokens: list[ManualToken] | None = None

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL doit commencer par http:// ou https://")
        return v


class SessionResponse(BaseModel):
    session_id: str
    status: str
    target_url: str
