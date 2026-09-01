# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import Protocol

from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty


class InferenceModule(Protocol):
    """Protocol for property inference modules."""

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]: ...
