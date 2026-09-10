# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import importlib.metadata

import structlog

log = structlog.get_logger()


class InferenceRegistry:
    """Registre des modules d'inférence de propriétés de sécurité.

    Les modules built-in sont enregistrés via InferenceRegistry.default().
    Les modules tiers sont découverts via entry_points 'hdwp.inference'.
    """

    def __init__(self) -> None:
        self._modules: dict[str, object] = {}

    def register(self, name: str, module: object) -> None:
        """Enregistre un module d'inférence."""
        if name in self._modules:
            log.warning("inference.override", name=name)
        self._modules[name] = module

    def discover(self) -> None:
        """Découvre les modules tiers via entry_points 'hdwp.inference'."""
        for ep in importlib.metadata.entry_points(group="hdwp.inference"):
            try:
                if ep.name in self._modules:
                    continue  # built-in enregistré explicitement prend la priorité
                cls = ep.load()
                self.register(ep.name, cls())
                log.debug("inference.discovered", name=ep.name)
            except Exception as exc:  # noqa: BLE001
                log.warning("inference.ep_load_failed", ep=ep.name, error=str(exc))

    def list_active(self) -> list[object]:
        """Retourne tous les modules actifs."""
        return list(self._modules.values())

    @classmethod
    def _builtin_modules(cls) -> list[tuple[str, type]]:
        from hdwp.core.property_engine.inference.authorization import AuthorizationInference
        from hdwp.core.property_engine.inference.coherence import CoherenceInference
        from hdwp.core.property_engine.inference.concurrency import ConcurrencyInference
        from hdwp.core.property_engine.inference.confidentiality import ConfidentialityInference
        from hdwp.core.property_engine.inference.http_semantics import HttpSemanticsInference
        from hdwp.core.property_engine.inference.integrity import IntegrityInference
        from hdwp.core.property_engine.inference.state import StateInference
        from hdwp.core.property_engine.inference.temporal import TemporalInference
        from hdwp.core.security_model.invariant_deriver import InvariantDeriver

        return [
            ("authorization", AuthorizationInference),
            ("confidentiality", ConfidentialityInference),
            ("state", StateInference),
            ("integrity", IntegrityInference),
            ("coherence", CoherenceInference),
            ("temporal", TemporalInference),
            ("concurrency", ConcurrencyInference),
            ("http_semantics", HttpSemanticsInference),  # verbe HTTP × structure path
            ("invariant_deriver", InvariantDeriver),     # invariants dérivés des observations
        ]

    @classmethod
    def default(cls) -> InferenceRegistry:
        """Crée un registry avec les 7 modules built-in + découverte entry_points."""
        reg = cls()
        for name, module_cls in cls._builtin_modules():
            reg.register(name, module_cls())
        reg.discover()
        return reg

    @classmethod
    def default_with_kb_stats(
        cls, kb_stats: dict[tuple[str, str], dict[str, float]]
    ) -> InferenceRegistry:
        """Registry with KB stats injected into modules that accept them."""
        reg = cls()
        for name, module_cls in cls._builtin_modules():
            try:
                mod = module_cls(kb_stats=kb_stats)
            except TypeError:
                mod = module_cls()
            reg.register(name, mod)
        reg.discover()
        return reg
