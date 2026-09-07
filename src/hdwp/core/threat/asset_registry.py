# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, EndpointNode, ParameterNode


class AssetSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    CRITICAL = "CRITICAL"


_CRITICAL_FIELDS = frozenset({
    "price", "amount", "balance", "total", "credit",
    "payment", "salary", "cost", "fee", "charge",
})

_SENSITIVE_FIELDS = frozenset({
    "email", "phone", "ssn", "dob", "birth", "address",
    "password", "token", "secret", "api_key", "credit_card",
})

_UUID_PATTERN = re.compile(r"\{[^}]*(?:id|uuid)[^}]*\}", re.IGNORECASE)
_ADMIN_PATTERN = re.compile(r"/admin(?:/|$)", re.IGNORECASE)


class AssetRegistry:
    def classify_endpoint(self, ep: EndpointNode, params: list[ParameterNode]) -> AssetSensitivity:
        if _ADMIN_PATTERN.search(ep.path):
            return AssetSensitivity.INTERNAL

        param_names = {p.name.lower() for p in params if p.id in ep.parameters}
        if param_names & _CRITICAL_FIELDS:
            return AssetSensitivity.CRITICAL
        if param_names & _SENSITIVE_FIELDS:
            return AssetSensitivity.SENSITIVE

        if _UUID_PATTERN.search(ep.path):
            return AssetSensitivity.SENSITIVE

        for p in params:
            if p.id in ep.parameters and p.semantic == "id_ref":
                return AssetSensitivity.SENSITIVE

        return AssetSensitivity.PUBLIC

    def classify_all(self, model: ApplicationModelData) -> dict[str, AssetSensitivity]:
        result: dict[str, AssetSensitivity] = {}
        for ep in model.endpoints:
            result[ep.path] = self.classify_endpoint(ep, model.parameters)
        return result
