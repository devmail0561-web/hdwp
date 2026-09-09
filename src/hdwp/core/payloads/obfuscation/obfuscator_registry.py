# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ObfuscatorRegistry: techniques d'obfuscation payload-spécifiques.

Différence Encoding vs Obfuscation:
- Encoding: transformation syntaxique (URL, Base64, Unicode)
- Obfuscation: transformation sémantique (SQL comments, CMDi variables, XSS event handlers)

Design:
- ObfuscationTechnique: (name, payload_type, apply, description, complexity)
- Registry thread-safe avec indexation par payload_type
- Génération de variantes avec max_combinations
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

import structlog

log = structlog.get_logger()


@dataclass
class ObfuscationTechnique:
    """Technique d'obfuscation pour un type de payload.

    Attributes:
        name: Identifiant unique (ex: sql_inline_comments)
        payload_type: Type de payload (ex: sqli, cmdi, xss)
        apply: Fonction d'obfuscation (payload: str) -> str
        description: Description de la technique
        complexity: Niveau de complexité (1-10) pour priorisation
    """
    name: str
    payload_type: str
    apply: Callable[[str], str]
    description: str
    complexity: int = 1


class ObfuscatorRegistry:
    """Singleton thread-safe pour gestion centralisée des obfuscators."""

    _instance: ObfuscatorRegistry | None = None
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
        self._obfuscators: dict[str, ObfuscationTechnique] = {}
        self._type_index: dict[str, list[str]] = {}  # payload_type -> [obfuscator_names]
        self._initialized = True
        self._load_builtins()

    def _load_builtins(self) -> None:
        """Charge les 20 obfuscators built-in."""
        # SQLi obfuscators (10)
        from hdwp.core.payloads.obfuscation.obfuscators.sqli import (
            SQLI_OBFUSCATORS,
        )
        # CMDi obfuscators (8)
        from hdwp.core.payloads.obfuscation.obfuscators.cmdi import (
            CMDI_OBFUSCATORS,
        )
        # XSS obfuscators (2)
        from hdwp.core.payloads.obfuscation.obfuscators.xss import (
            XSS_OBFUSCATORS,
        )

        for obfuscator in SQLI_OBFUSCATORS + CMDI_OBFUSCATORS + XSS_OBFUSCATORS:
            self.register(obfuscator)

        log.info("obfuscator_registry.loaded_builtins", count=len(self._obfuscators))

    def register(self, technique: ObfuscationTechnique) -> None:
        """Enregistre une technique d'obfuscation."""
        if technique.name in self._obfuscators:
            log.warning("obfuscator_registry.duplicate", name=technique.name)
            return

        self._obfuscators[technique.name] = technique

        # Indexation par payload_type
        if technique.payload_type not in self._type_index:
            self._type_index[technique.payload_type] = []
        self._type_index[technique.payload_type].append(technique.name)

    def get_by_type(self, payload_type: str) -> list[ObfuscationTechnique]:
        """Récupère les obfuscators pour un type de payload."""
        names = self._type_index.get(payload_type, [])
        return [self._obfuscators[name] for name in names]

    def obfuscate(self, payload: str, technique_name: str) -> str:
        """Applique une technique d'obfuscation."""
        technique = self._obfuscators.get(technique_name)
        if technique is None:
            log.warning("obfuscator_registry.unknown_technique", name=technique_name)
            return payload

        try:
            return technique.apply(payload)
        except Exception as exc:
            log.error("obfuscator_registry.apply_failed", technique=technique_name, error=str(exc))
            return payload

    def generate_variants(
        self,
        payload: str,
        payload_type: str,
        max_combinations: int = 10,
    ) -> list[tuple[str, str]]:
        """Génère des variantes obfusquées d'un payload.

        Args:
            payload: Payload original
            payload_type: Type (sqli, cmdi, xss)
            max_combinations: Limite max de variantes

        Returns:
            Liste de (payload_obfuscated, technique_name)
        """
        techniques = self.get_by_type(payload_type)
        if not techniques:
            return []

        # Trier par complexité (techniques simples en premier)
        techniques.sort(key=lambda t: t.complexity)

        variants = []
        for technique in techniques[:max_combinations]:
            try:
                obfuscated = technique.apply(payload)
                if obfuscated != payload:
                    variants.append((obfuscated, technique.name))
            except Exception as exc:
                log.debug("obfuscator_registry.variant_failed", technique=technique.name, error=str(exc))
                continue

        return variants[:max_combinations]

    def list_obfuscators(self) -> list[str]:
        """Liste tous les obfuscators enregistrés."""
        return list(self._obfuscators.keys())


# Instance globale (singleton pattern)
_global_obfuscator_registry: ObfuscatorRegistry | None = None


def get_obfuscator_registry() -> ObfuscatorRegistry:
    """Retourne l'instance globale de l'ObfuscatorRegistry."""
    global _global_obfuscator_registry
    if _global_obfuscator_registry is None:
        _global_obfuscator_registry = ObfuscatorRegistry()
    return _global_obfuscator_registry
