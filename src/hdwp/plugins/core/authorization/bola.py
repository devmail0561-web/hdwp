# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
)
from hdwp.plugins.base import HDWPPlugin


class BOLAPlugin(HDWPPlugin):
    """Detects Broken Object Level Authorization (BOLA/IDOR) vulnerabilities."""

    @property
    def id(self) -> str:
        return "core.authorization.bola"

    @property
    def name(self) -> str:
        return "BOLA Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "authorization"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-639"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties: list[SecurityProperty] = []
        for param in model.parameters:
            if param.affects_object and param.type_inferred in ("integer", "uuid"):
                properties.append(
                    SecurityProperty(
                        type=PropertyType.AUTHORIZATION,
                        formal_statement=(
                            f"BOLA: access via '{param.name}' requires ownership verification"
                        ),
                        model_nodes=[param.id],
                        inference_confidence=0.85,
                    )
                )
        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        for param in model.parameters:
            if param.affects_object and param.type_inferred in ("integer", "uuid"):
                hypotheses.append(
                    Hypothesis(
                        source_plugin=self.id,
                        property_id="",
                        statement=(
                            f"Object accessed via parameter '{param.name}' lacks ownership "
                            "verification — changing the ID returns another user's data"
                        ),
                        priority="HIGH",
                        priority_rationale="BOLA/IDOR: direct access to other users' objects",
                        required_experiments=[
                            ExperimentSpec(
                                mutation_type="object_ref_change",
                                base_request=NormalizedRequest(method="GET", url=""),
                                mutation_params={
                                    "parameter_name": param.name,
                                    "parameter_location": param.location,
                                },
                                description=f"Change '{param.name}' to another user's object ID",
                            ),
                        ],
                    )
                )
        return hypotheses
