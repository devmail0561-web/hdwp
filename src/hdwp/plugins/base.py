# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from abc import ABC, abstractmethod

from hdwp.core.model.schemas import ApplicationModelData, Hypothesis, SecurityProperty


class HDWPPlugin(ABC):
    """Base class for all HDWP plugins."""

    @property
    @abstractmethod
    def id(self) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> str: ...

    @property
    def description(self) -> str:
        return ""

    @property
    def owasp_mapping(self) -> list[str]:
        return []

    @property
    def cwe_mapping(self) -> list[str]:
        return []

    @property
    def data_access(self) -> str:
        return "MODEL_READ"

    def tech_stack_required(self) -> set[str]:
        """Tags tech_stack requis pour activer ce plugin (ex: {'framework:spring'}).
        Retourne un set vide = actif sur toutes les cibles (comportement par défaut).
        """
        return set()

    async def on_refresh(self, signatures: list[dict]) -> None:
        """Appelé quand de nouvelles signatures CVE sont disponibles pour ce plugin.

        Les plugins peuvent mettre à jour leurs payload lists ou filtres en réponse.
        Les signatures sont des dicts avec les clés : vuln_id, package, ecosystem,
        version_range, fixed_version, cvss_score, owasp_category, attack_vector.
        """
        pass

    async def on_load(self) -> None:
        pass

    async def on_model_ready(self, model: ApplicationModelData) -> None:
        pass

    async def on_unload(self) -> None:
        pass

    @abstractmethod
    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        ...

    @abstractmethod
    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        ...

    def register_mutations(self) -> list[dict]:
        """Enregistrer des mutations custom dans le MutationRegistry.

        Retourne une liste de dicts pour mutation_registry.register().
        Chaque dict doit contenir : name, owasp_category, cwe_id, remediation,
        et optionnellement : assess_violation, compute_specificity,
        plan_experiment, apply_mutation.
        """
        return []
