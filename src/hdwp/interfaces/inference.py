# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty


@runtime_checkable
class InferenceModuleProtocol(Protocol):
    """Contrat pour tout module d'inférence de propriétés de sécurité.

    Implémentation minimale :
        class MyInference:
            def provider_id(self) -> str: return "mypkg.my_inference"
            def infer(self, model) -> list[SecurityProperty]: return []
    """

    def provider_id(self) -> str:
        """Identifiant stable et unique du module. Convention : 'package.nom'."""
        ...

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Analyse le modèle et retourne les propriétés de sécurité détectées."""
        ...
