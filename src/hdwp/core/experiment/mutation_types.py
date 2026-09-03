# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Protocoles pour les fonctions de planification et d'application de mutations.

Ces protocoles definissent les signatures que les fonctions de planification
et d'application doivent respecter pour etre enregistrees dans le MutationRegistry.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConcreteExperimentPlan,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
)

if TYPE_CHECKING:
    from hdwp.core.experiment.session_manager import SessionManager


class PlanFunction(Protocol):
    """Signature d'une fonction de planification de mutation."""

    def __call__(
        self,
        hypothesis: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]: ...


class ApplyFunction(Protocol):
    """Signature d'une fonction d'application de mutation."""

    def __call__(
        self,
        plan: ConcreteExperimentPlan,
        session_manager: SessionManager,
    ) -> NormalizedRequest: ...
