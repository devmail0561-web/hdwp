# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
EncoderRegistry: gestionnaire centralisé des stratégies d'encodage.

Fournit:
- Enregistrement dynamique d'encoders custom
- Application de chaînes d'encodage multi-niveaux
- Génération de variantes auto avec limites
- Thread-safe (frozen dataclasses + lock)

Phase 1: Wrapper autour des 25 EncodingStrategy de encoding_pipeline.py
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from hdwp.core.experiment.encoding_pipeline import EncodingStrategy

log = structlog.get_logger()


class EncoderRegistry:
    """Singleton thread-safe pour gestion centralisée des encoders.

    Design pattern:
    1. Chargement des 25 encoders built-in au démarrage
    2. Enregistrement dynamique d'encoders custom via plugins
    3. Application de chaînes d'encodage (nested encoding)
    4. Génération de variantes auto (max_combinations)
    """

    _instance: EncoderRegistry | None = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._encoders: dict[str, EncodingStrategy] = {}
        self._waf_index: dict[str, list[str]] = {}  # waf_tag -> [encoder_names]
        self._initialized = True
        self._load_builtins()

    def _load_builtins(self) -> None:
        """Charge les 25 encoders built-in depuis encoding_pipeline."""
        from hdwp.core.experiment.encoding_pipeline import ENCODING_STRATEGIES

        for strategy in ENCODING_STRATEGIES:
            self.register(strategy)
        log.info("encoder_registry.loaded_builtins", count=len(ENCODING_STRATEGIES))

    def register(self, strategy: EncodingStrategy) -> None:
        """Enregistre un encoder (built-in ou custom).

        Args:
            strategy: EncodingStrategy avec name, transform, waf_effective_against

        Raises:
            ValueError: si name existe déjà (override interdit)
        """
        if strategy.name in self._encoders:
            log.warning("encoder_registry.duplicate", name=strategy.name)
            return

        self._encoders[strategy.name] = strategy

        # Indexation par WAF tag pour lookup rapide
        for waf_tag in strategy.waf_effective_against:
            if waf_tag not in self._waf_index:
                self._waf_index[waf_tag] = []
            self._waf_index[waf_tag].append(strategy.name)

    def get_by_name(self, name: str) -> EncodingStrategy | None:
        """Récupère un encoder par son nom."""
        return self._encoders.get(name)

    def get_by_waf(self, waf_tag: str, max_count: int = 3) -> list[EncodingStrategy]:
        """Récupère les encoders efficaces contre un WAF.

        Args:
            waf_tag: Tag WAF (ex: waf:cloudflare)
            max_count: Nombre max d'encoders à retourner

        Returns:
            Liste d'EncodingStrategy triées par priorité (spécifique > générique)
        """
        # Spécifiques au WAF
        specific = [self._encoders[name] for name in self._waf_index.get(waf_tag, [])]
        # Génériques (fallback)
        generic = [self._encoders[name] for name in self._waf_index.get("waf:generic", [])]

        return (specific + generic)[:max_count]

    def apply_chain(self, payload: str, chain: list[str]) -> str:
        """Applique une chaîne d'encodages successifs.

        Args:
            payload: Payload original
            chain: Liste de noms d'encoders (ex: ["url_encode", "base64"])

        Returns:
            Payload encodé (niveaux successifs)

        Example:
            >>> apply_chain("<script>", ["url_encode", "base64"])
            "JTNDc2NyaXB0JTNF"  # base64(url_encode("<script>"))
        """
        result = payload
        for encoder_name in chain:
            strategy = self._encoders.get(encoder_name)
            if strategy is None:
                log.warning("encoder_registry.unknown_encoder", name=encoder_name)
                continue
            try:
                result = strategy.transform(result)
            except Exception as exc:
                log.error("encoder_registry.apply_failed", encoder=encoder_name, error=str(exc))
                continue
        return result

    def generate_variants(
        self,
        payload: str,
        encoding_chains: list[list[str]],
        max_combinations: int = 20,
    ) -> list[tuple[str, list[str]]]:
        """Génère des variantes de payloads avec encodages multiples.

        Args:
            payload: Payload original
            encoding_chains: Liste de chaînes d'encodage
            max_combinations: Limite max de variantes (évite explosion combinatoire)

        Returns:
            Liste de (payload_encoded, chain_applied)

        Example:
            >>> generate_variants("' OR 1=1", [["url_encode"], ["base64"], ["url_encode", "base64"]], max_combinations=20)
            [
                ("%27%20OR%201%3D1", ["url_encode"]),
                ("JyBPUiAxPTE=", ["base64"]),
                ("JTI3JTIwT1IlMjAlMjAlM0QxJTNEMQ==", ["url_encode", "base64"]),
            ]
        """
        variants = []
        for chain in encoding_chains[:max_combinations]:
            try:
                encoded = self.apply_chain(payload, chain)
                if encoded != payload:  # Skip si encoding n'a rien changé
                    variants.append((encoded, chain))
            except Exception as exc:
                log.debug("encoder_registry.variant_failed", chain=chain, error=str(exc))
                continue

        return variants[:max_combinations]

    def list_encoders(self) -> list[str]:
        """Liste tous les encoders enregistrés."""
        return list(self._encoders.keys())


# Instance globale (singleton pattern)
_global_encoder_registry: EncoderRegistry | None = None


def get_encoder_registry() -> EncoderRegistry:
    """Retourne l'instance globale de l'EncoderRegistry."""
    global _global_encoder_registry
    if _global_encoder_registry is None:
        _global_encoder_registry = EncoderRegistry()
    return _global_encoder_registry
