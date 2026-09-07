# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Spring Boot Actuator scanner — activé uniquement si framework:spring détecté."""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
    generate_id,
)
from hdwp.plugins.base import HDWPPlugin

_ACTUATOR_PATHS = [
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/loggers",
    "/actuator/info",
    "/actuator/health",
    "/management/env",
    "/management/heapdump",
]


class SpringActuatorPlugin(HDWPPlugin):
    """Scan des endpoints Spring Boot Actuator exposés sans protection."""

    @property
    def id(self) -> str:
        return "core.configuration.spring_actuator"

    @property
    def name(self) -> str:
        return "Spring Boot Actuator Scanner"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "configuration"

    def tech_stack_required(self) -> set[str]:
        return {"framework:spring", "server:tomcat", "server:jetty", "server:undertow"}

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.COHERENCE,
            formal_statement="Spring Boot Actuator endpoints may expose internal state",
            model_nodes=[],
            inference_confidence=0.80,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        base_url = next(
            (ep.path.split("/actuator")[0] for ep in model.endpoints if "/actuator" in ep.path),
            "",
        )
        hypotheses = []
        for path in _ACTUATOR_PATHS:
            full_path = base_url + path
            # Ne pas tester un path déjà connu comme non-existant
            hypotheses.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=f"[Spring Actuator] {full_path} est accessible sans authentification",
                priority="HIGH",
                priority_rationale="Actuator exposé → fuite de config, env vars, heap dump",
                required_experiments=[ExperimentSpec(
                    mutation_type="privilege_escalation",
                    base_request=NormalizedRequest(method="GET", url=full_path),
                    mutation_params={
                        "endpoint_path": full_path,
                        "method": "GET",
                        "actuator_path": path,
                    },
                    description=f"Spring Actuator: GET {path}",
                )],
            ))
        return hypotheses

    def register_mutations(self) -> list[dict]:
        return []
