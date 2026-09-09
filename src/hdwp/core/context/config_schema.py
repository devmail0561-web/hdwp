# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


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
    # Chaîne de fallback : proxies à essayer si tor_proxy est injoignable.
    # Testés dans l'ordre au démarrage du moteur. null = connexion directe.
    # Exemple : ["http://127.0.0.1:8080", null]
    proxy_fallback: list[str | None] = []
    # Mode exploration continue : le moteur itère après la passe initiale tant que
    # de nouvelles hypothèses sont disponibles (pivots, confirmations, désambiguïsations).
    continuous: bool = False
    scan_time_limit_minutes: int = 60  # durée max du mode continu (0 = illimité)
    # Chemin vers un fichier JSON de signatures CVE pour les missions en réseau isolé.
    offline_cve_db: str | None = None


class PluginConfig(BaseModel):
    enabled: list[str] = []   # vide = tous les plugins découverts actifs
    disabled: list[str] = []  # liste noire explicite (IDs à exclure)
    config: dict[str, dict[str, Any]] = {}


class ExploitStrategyConfig(BaseModel):
    enabled: list[str] = []
    disabled: list[str] = []
    config: dict[str, dict[str, Any]] = {}


class TuningConfig(BaseModel):
    """Réglages fins du moteur — toutes les valeurs ont des défauts sûrs."""

    # Seuil de confirmation (score global confidence → CONFIRMED)
    confirmed_threshold: float = 0.85

    # Seuils de sévérité du rapport final
    severity_high_threshold: float = 0.90
    severity_medium_threshold: float = 0.80

    # Seuils de score de priorité des hypothèses
    priority_high_threshold: float = 0.60
    priority_medium_threshold: float = 0.30

    # Poids du modèle de confiance 5 dimensions
    weight_oracle_strength: float = 0.25
    weight_reproducibility: float = 0.30
    weight_observation_quality: float = 0.15
    weight_behavioral_specificity: float = 0.15
    weight_experiment_coverage: float = 0.15

    # Poids d'impact par type de propriété (clés = PropertyType.value)
    # {} = utiliser les BASE_WEIGHTS définis dans knowledge/base.py
    impact_weights: dict[str, float] = {}

    # Boost de confidence BOLA quand deux rôles distincts obtiennent status=200
    bola_role_confirmation_boost: float = 0.15

    # ── V2 Confidence Model Weights (10 dimensions logistiques) ──────────────────
    # Permettent de configurer les poids du modèle V2 via YAML
    # Valeurs par défaut = V2_DEFAULT_WEIGHTS de confidence.py
    v2_weight_oracle_strength: float = 1.8
    v2_weight_reproducibility: float = 2.2
    v2_weight_observation_quality: float = 0.8
    v2_weight_behavioral_specificity: float = 1.0
    v2_weight_experiment_coverage: float = 0.7
    v2_weight_temporal_signal: float = 1.5
    v2_weight_crossrole_signal: float = 1.8
    v2_weight_invariant_violated: float = 2.5
    v2_weight_waf_bypass_success: float = 0.6
    v2_weight_causal_depth: float = 1.2
    v2_bias: float = -4.0

    # Phase 0.1: Validation range [-6, 6] pour éviter sigmoid explosion
    @field_validator(
        'v2_weight_oracle_strength', 'v2_weight_reproducibility',
        'v2_weight_observation_quality', 'v2_weight_behavioral_specificity',
        'v2_weight_experiment_coverage', 'v2_weight_temporal_signal',
        'v2_weight_crossrole_signal', 'v2_weight_invariant_violated',
        'v2_weight_waf_bypass_success', 'v2_weight_causal_depth',
        'v2_bias'
    )
    @classmethod
    def validate_v2_weight_range(cls, v: float) -> float:
        """Valide que les poids V2 sont dans [-6, 6] (ADR-ML-009)."""
        if not -6.0 <= v <= 6.0:
            raise ValueError(f"V2 weight must be in [-6, 6], got {v}")
        return v


class HDWPContextConfig(BaseModel):
    target: TargetConfig
    scope: ScopeConfig
    threat_model: ThreatModelConfig = ThreatModelConfig()
    roles: list[RoleConfig] = []
    options: OptionsConfig = OptionsConfig()
    plugins: PluginConfig = PluginConfig()
    exploit_strategies: ExploitStrategyConfig = ExploitStrategyConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    llm: LLMConfig = LLMConfig()
    tuning: TuningConfig = TuningConfig()
