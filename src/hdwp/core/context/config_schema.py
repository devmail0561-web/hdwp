# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


class LLMConfig(BaseModel):
    """Configuration de la couche LLM optionnelle (ADR-002 : non-décisionnel)."""

    enabled: bool = False
    provider: Literal["anthropic", "openai", "ollama"] = "anthropic"
    model: str = "claude-sonnet-4-6"
    # La clé API est toujours résolue depuis l'environnement, jamais stockée ici.
    # Conventions : ANTHROPIC_API_KEY, OPENAI_API_KEY, ou HDWP_LLM_API_KEY.
    base_url: str | None = None  # requis pour ollama: http://localhost:11434/v1


class DiscoveryConfig(BaseModel):
    openapi_spec: str | None = None
    seed_endpoints: list[str] = []


class TargetConfig(BaseModel):
    base_url: str
    name: str


class ScopeConfig(BaseModel):
    include: list[str]
    exclude: list[str] = []


class CredentialConfig(BaseModel):
    type: Literal[
        "bearer", "basic", "cookie", "api_key",
        "oauth2_password",           # grant_type=password (username+password → token)
        "oauth2_client_credentials", # grant_type=client_credentials (machine-to-machine)
    ]
    token: str | None = None
    username: str | None = None
    password: str | None = None
    header_name: str | None = None
    header_value: str | None = None
    # OAuth2-specific — toujours None pour les autres types
    token_endpoint: str | None = None   # ex: ${TOKEN_ENDPOINT}
    client_id: str | None = None        # ex: ${CLIENT_ID}
    client_secret: str | None = None    # ex: ${CLIENT_SECRET}
    scope: str | None = None            # ex: "read write admin"
    refresh_token: str | None = None    # stocké automatiquement si retourné


class RoleConfig(BaseModel):
    name: str
    credentials: CredentialConfig | None = None


class ThreatModelConfig(BaseModel):
    focus: list[str] = []
    business_logic: bool = True


class OptionsConfig(BaseModel):
    allow_write: bool = False
    max_requests_per_minute: int = 60
    max_concurrent_experiments: int = 3  # expériences en parallèle dans le pipeline réactif
    language: str = "en"
    knowledge_db: str | None = None  # None → ~/.hdwp/knowledge.db
    # Proxy sortant — socks5h://127.0.0.1:9150 = Tor Browser par défaut.
    # Mettre à null pour connexion directe, ou une URL HTTP(S) pour un proxy MITM type Burp.
    tor_proxy: str | None = "socks5h://127.0.0.1:9150"


class PluginConfig(BaseModel):
    enabled: list[str] = []   # vide = tous les plugins découverts actifs
    disabled: list[str] = []  # liste noire explicite (IDs à exclure)
    config: dict[str, dict[str, Any]] = {}


class HDWPContextConfig(BaseModel):
    target: TargetConfig
    scope: ScopeConfig
    threat_model: ThreatModelConfig = ThreatModelConfig()
    roles: list[RoleConfig] = []
    options: OptionsConfig = OptionsConfig()
    plugins: PluginConfig = PluginConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    llm: LLMConfig = LLMConfig()
