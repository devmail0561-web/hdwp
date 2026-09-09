# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
BypassRegistry: stratégies de bypass WAF au niveau transport/protocol.

Différence avec encoding_pipeline.py:
- encoding_pipeline: transforme la VALEUR du payload (encodage)
- BypassRegistry: transforme la STRUCTURE de la requête (headers, body framing, protocol)

Chargement:
1. waf_signatures.yaml: signatures WAF → effective_bypasses indexés par waf_id
2. EVASION_STRATEGIES + TIMING_STRATEGIES + PROTOCOL_STRATEGIES: 15 stratégies built-in

Design pattern identique à EncoderRegistry et ObfuscatorRegistry.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TYPE_CHECKING

import structlog
import yaml

if TYPE_CHECKING:
    from hdwp.core.model.schemas import NormalizedRequest

log = structlog.get_logger()


@dataclass
class BypassResult:
    """Résultat de l'application d'une stratégie bypass.

    Attributes:
        request: NormalizedRequest modifié (headers/body/url)
        raw_override: Bytes bruts à envoyer comme body HTTP.
            Quand défini, engine._send() utilise content=raw_override au lieu du body normal.
            Utilisé par cl_te_smuggling, te_cl_smuggling, chunked_abuse, slowloris.
        strategy_name: Nom de la stratégie appliquée
    """
    request: NormalizedRequest
    raw_override: bytes | None = None
    strategy_name: str = ""


@dataclass
class BypassStrategy:
    """Stratégie de bypass WAF au niveau transport/protocol.

    Attributes:
        name: Identifiant unique (ex: "whitespace_variation")
        category: "evasion" | "timing" | "protocol"
        apply: Fonction (NormalizedRequest, dict[str, Any]) -> BypassResult
        description: Description humaine
        risk_level: "low" | "medium" | "high" — utilisé pour l'ordering dans get_strategies_for_waf
        requires_special_execution: True si raw_override doit être utilisé comme body HTTP brut
    """
    name: str
    category: Literal["evasion", "timing", "protocol"]
    apply: Callable[[NormalizedRequest, dict[str, Any]], BypassResult]
    description: str
    risk_level: Literal["low", "medium", "high"] = "medium"
    requires_special_execution: bool = False


@dataclass(frozen=True)
class WafSignature:
    """Signature WAF chargée depuis waf_signatures.yaml (immutable).

    Attributes:
        waf_id: Identifiant WAF (ex: "cloudflare") — correspond au suffixe de "waf:cloudflare"
        headers: Noms de headers de réponse dont la présence identifie le WAF
        server_patterns: Substrings attendus dans le header Server
        body_patterns: Substrings attendus dans le corps de réponse 403/503
        block_status_codes: Codes HTTP utilisés par ce WAF pour bloquer
        effective_bypasses: Noms ordonnés de stratégies efficaces (index de priorité)
    """
    waf_id: str
    headers: tuple[str, ...]
    server_patterns: tuple[str, ...]
    body_patterns: tuple[str, ...]
    block_status_codes: tuple[int, ...]
    effective_bypasses: tuple[str, ...]


class BypassRegistry:
    """Singleton thread-safe pour stratégies bypass WAF transport/protocol.

    Chargement YAML au démarrage, cache mémoire, accès lecture-seule après init.
    """

    _instance: BypassRegistry | None = None
    _lock = threading.Lock()

    def __new__(cls) -> BypassRegistry:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._strategies: dict[str, BypassStrategy] = {}
        self._waf_index: dict[str, list[str]] = {}   # waf_id → [strategy_names ordonnés]
        self._waf_signatures: dict[str, WafSignature] = {}
        self._initialized = True
        self._load_waf_signatures()
        self._load_builtins()

    def _load_waf_signatures(self, yaml_path: Path | None = None) -> None:
        """Charge waf_signatures.yaml. Dégradation gracieuse si fichier absent."""
        if yaml_path is None:
            yaml_path = Path(__file__).parent / "waf_signatures.yaml"

        if not yaml_path.exists():
            log.warning("bypass_registry.waf_signatures_missing", path=str(yaml_path))
            return

        try:
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            log.error("bypass_registry.waf_signatures_load_failed", error=str(exc))
            return

        for waf_id, cfg in raw.items():
            if not isinstance(cfg, dict):
                continue
            try:
                sig = WafSignature(
                    waf_id=waf_id,
                    headers=tuple(cfg.get("headers") or []),
                    server_patterns=tuple(cfg.get("server_patterns") or []),
                    body_patterns=tuple(cfg.get("body_patterns") or []),
                    block_status_codes=tuple(cfg.get("block_status_codes") or [403]),
                    effective_bypasses=tuple(cfg.get("effective_bypasses") or []),
                )
                self._waf_signatures[waf_id] = sig
                self._waf_index[waf_id] = list(sig.effective_bypasses)
            except Exception as exc:
                log.warning("bypass_registry.waf_signature_parse_error",
                            waf_id=waf_id, error=str(exc))

        log.info("bypass_registry.waf_signatures_loaded", count=len(self._waf_signatures))

    def _load_builtins(self) -> None:
        """Charge les 15 stratégies depuis evasion.py, timing.py, protocol.py."""
        from hdwp.core.payloads.waf_bypass.strategies.evasion import EVASION_STRATEGIES
        from hdwp.core.payloads.waf_bypass.strategies.timing import TIMING_STRATEGIES
        from hdwp.core.payloads.waf_bypass.strategies.protocol import PROTOCOL_STRATEGIES

        all_strategies = EVASION_STRATEGIES + TIMING_STRATEGIES + PROTOCOL_STRATEGIES
        for strategy in all_strategies:
            self.register(strategy)
        log.info("bypass_registry.loaded_builtins", count=len(all_strategies))

    def register(self, strategy: BypassStrategy) -> None:
        """Enregistre une stratégie. Duplicate name → warning + skip (pas d'override)."""
        if strategy.name in self._strategies:
            log.warning("bypass_registry.duplicate", name=strategy.name)
            return
        self._strategies[strategy.name] = strategy

    def get_by_name(self, name: str) -> BypassStrategy | None:
        """Retourne une stratégie par son nom exact."""
        return self._strategies.get(name)

    def get_strategies_for_waf(
        self,
        waf_tag: str,
        max_count: int = 3,
        category: Literal["evasion", "timing", "protocol"] | None = None,
    ) -> list[BypassStrategy]:
        """Retourne les stratégies ordonnées pour un WAF détecté.

        Args:
            waf_tag: "waf:cloudflare" (tag EndpointNode) OU "cloudflare" (waf_id YAML)
            max_count: Nombre max à retourner
            category: Filtre optionnel par catégorie

        Returns:
            Stratégies WAF-spécifiques en premier, puis generic en fallback.
        """
        waf_id = waf_tag.removeprefix("waf:")

        specific_names = self._waf_index.get(waf_id, [])
        generic_names = self._waf_index.get("generic", [])
        # Déduplique en préservant l'ordre (spécifiques d'abord)
        seen: set[str] = set()
        ordered_names: list[str] = []
        for name in specific_names + generic_names:
            if name not in seen:
                seen.add(name)
                ordered_names.append(name)

        result: list[BypassStrategy] = []
        for name in ordered_names:
            strategy = self._strategies.get(name)
            if strategy is None:
                continue
            if category is not None and strategy.category != category:
                continue
            result.append(strategy)
            if len(result) >= max_count:
                break

        return result

    def detect_waf_from_response(
        self,
        headers: dict[str, str],
        body: str = "",
        status_code: int = 403,
    ) -> str | None:
        """Détecte un WAF depuis headers/body de réponse.

        Returns "waf:<waf_id>" ou None. Complément à observation/waf_detector.py
        pour la détection inline pendant l'exécution des expériences.
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        server_value = headers_lower.get("server", "")

        for waf_id, sig in self._waf_signatures.items():
            if waf_id == "generic":
                continue

            # Détection de signature : headers/body sur TOUS les statuts (ex. cf-ray présent sur 200)
            # Le statut est un signal de blocage mais pas une condition de présence du WAF.
            matched = False

            for header_name in sig.headers:
                if header_name.lower() in headers_lower:
                    matched = True
                    break

            if not matched:
                for pattern in sig.server_patterns:
                    if pattern.lower() in server_value:
                        matched = True
                        break

            if not matched and status_code in sig.block_status_codes:
                # Body patterns uniquement sur les réponses de blocage pour limiter les faux positifs
                for pattern in sig.body_patterns:
                    if pattern.lower() in body_lower:
                        matched = True
                        break

            if matched:
                return f"waf:{waf_id}"

        # Fallback generic
        generic_sig = self._waf_signatures.get("generic")
        if generic_sig:
            for pattern in generic_sig.body_patterns:
                if pattern.lower() in body_lower:
                    return "waf:generic"

        return None

    def apply_bypass(
        self,
        strategy_name: str,
        request: NormalizedRequest,
        params: dict[str, Any] | None = None,
    ) -> BypassResult:
        """Applique une stratégie à une NormalizedRequest.

        Returns BypassResult(request=request_original) si stratégie inconnue.
        Ne lève jamais d'exception.
        """
        strategy = self._strategies.get(strategy_name)
        if strategy is None:
            log.debug("bypass_registry.unknown_strategy", name=strategy_name)
            return BypassResult(request=request, strategy_name=strategy_name)

        try:
            result = strategy.apply(request, params or {})
            result.strategy_name = strategy_name
            return result
        except Exception as exc:
            log.warning("bypass_registry.apply_failed", strategy=strategy_name, error=str(exc))
            return BypassResult(request=request, strategy_name=strategy_name)

    def list_strategies(self) -> list[str]:
        """Liste tous les noms de stratégies enregistrées."""
        return list(self._strategies.keys())

    def list_waf_signatures(self) -> list[str]:
        """Liste tous les waf_id connus depuis waf_signatures.yaml."""
        return list(self._waf_signatures.keys())

    @classmethod
    def reset_for_testing(cls) -> None:
        """Réinitialise le singleton. Miroir de PayloadDatabase.reset_for_testing."""
        global _global_bypass_registry
        with cls._lock:
            cls._instance = None
            _global_bypass_registry = None


_global_bypass_registry: BypassRegistry | None = None


def get_bypass_registry() -> BypassRegistry:
    """Retourne l'instance globale de BypassRegistry."""
    global _global_bypass_registry
    if _global_bypass_registry is None:
        _global_bypass_registry = BypassRegistry()
    return _global_bypass_registry
