# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty


class ConcurrencyInference:
    """Infers concurrency properties from the application model."""

    def provider_id(self) -> str:
        return "builtin.concurrency"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []
