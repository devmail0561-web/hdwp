# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""AnomalyProbingPlugin: detect unknown vulnerabilities via behavioral anomalies.

Tests type confusion and boundary values — no signature required.
A server that behaves unexpectedly on wrong-type or extreme inputs has
validation gaps that may lead to unknown exploitable conditions.
"""
from __future__ import annotations

import json

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
)
from hdwp.plugins.base import HDWPPlugin

_TYPE_CONFUSED_VALUES: dict[str, list] = {
    "integer": ["not_a_number", None, [], True],
    "string": [0, None, [], {"$ne": None}],
    "boolean": ["yes", 2, None, ""],
    "uuid": [0, "invalid-uuid-format", None],
    "number": ["NaN", None, [], "Infinity"],
}

_BOUNDARY_VALUES = [
    ("max_int32", 2147483647),
    ("min_int32", -2147483648),
    ("null_val", None),
    ("empty_string", ""),
    ("overflow_str", "A" * 10000),
    ("max_int64", 9223372036854775807),
    ("negative_one", -1),
    ("zero", 0),
]


class AnomalyProbingPlugin(HDWPPlugin):
    """Generates type confusion and boundary value hypotheses for anomaly detection."""

    @property
    def id(self) -> str:
        return "core.injection.anomaly_probing"

    @property
    def name(self) -> str:
        return "Anomaly Probing — Type Confusion + Boundary Values"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A03:2021", "A04:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-843", "CWE-190"]

    def infer_properties(self, model: ApplicationModelData) -> list:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []

        # Type confusion: for each param with known type, send wrong type
        for ep in model.endpoints[:5]:
            params = [
                p for p in model.parameters
                if p.id in ep.parameters
                and p.type_inferred in _TYPE_CONFUSED_VALUES
                and p.is_user_controlled
            ][:3]
            for param in params:
                for val in _TYPE_CONFUSED_VALUES[param.type_inferred][:2]:
                    hyps.append(Hypothesis(
                        source_plugin=self.id,
                        property_id="",
                        statement=(
                            f"[{ep.path}] '{param.name}' ({param.type_inferred}) "
                            f"accepte {type(val).__name__} — confusion de type potentielle"
                        ),
                        priority="MEDIUM",
                        priority_rationale="Type confusion → PHP juggling, JS == bypass, logique cassée",
                        required_experiments=[ExperimentSpec(
                            mutation_type="type_confusion",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": json.dumps(val),
                                "endpoint_path": ep.path,
                            },
                            description=f"Type confusion: {param.name}={val!r}",
                        )],
                    ))

        # Boundary values: detect integer overflows, null dereferences, buffers
        for ep in model.endpoints[:3]:
            candidates = [p for p in model.parameters if p.id in ep.parameters][:2]
            for param in candidates:
                for label, val in _BOUNDARY_VALUES[:4]:
                    hyps.append(Hypothesis(
                        source_plugin=self.id,
                        property_id="",
                        statement=(
                            f"[{ep.path}] '{param.name}' avec valeur limite '{label}' "
                            f"— anomalie comportementale possible"
                        ),
                        priority="LOW",
                        priority_rationale="Valeurs limites révèlent comportements inattendus sans signature",
                        required_experiments=[ExperimentSpec(
                            mutation_type="boundary_value",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "parameter_name": param.name,
                                "parameter_location": param.location,
                                "payload": json.dumps(val),
                                "endpoint_path": ep.path,
                            },
                            description=f"Boundary: {param.name}={label}",
                        )],
                    ))

        return hyps
