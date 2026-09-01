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
    def owasp_mapping(self) -> list[str]:
        return []

    @property
    def cwe_mapping(self) -> list[str]:
        return []

    @property
    def data_access(self) -> str:
        return "MODEL_READ"

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
