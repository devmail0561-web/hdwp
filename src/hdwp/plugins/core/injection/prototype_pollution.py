# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""PrototypePollutionPlugin: détecte la pollution de prototype JavaScript (CWE-1321)."""
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

JS_TECH_INDICATORS = (
    "node", "express", "nestjs", "javascript", "typescript",
    "next.js", "nuxt", "fastify", "koa",
)

PROTO_PAYLOADS = [
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '{"__proto__": {"toString": "pwned"}}',
]


class PrototypePollutionPlugin(HDWPPlugin):
    """Détecte la pollution de prototype dans les APIs JavaScript/Node.js."""

    @property
    def id(self) -> str:
        return "core.injection.prototype_pollution"

    @property
    def name(self) -> str:
        return "Prototype Pollution"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A03:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-1321"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        tech_stack = getattr(model, "tech_stack", [])
        uses_js = any(
            indicator in t.lower()
            for t in tech_stack
            for indicator in JS_TECH_INDICATORS
        )
        if not uses_js:
            return []
        body_params = [
            p for p in model.parameters
            if p.location == "body" and p.type_inferred in ("object", "string")
        ]
        if not body_params:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement=(
                "JSON parsing must not allow prototype pollution via __proto__ or constructor keys"
            ),
            model_nodes=[p.id for p in body_params[:3]],
            inference_confidence=0.7,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        body_params = [
            p for p in model.parameters
            if p.location == "body" and p.type_inferred in ("object", "string")
        ][:3]
        if not body_params:
            return []
        hyps = []
        for param in body_params:
            for payload in PROTO_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le paramètre '{param.name}' est vulnérable à la pollution de prototype"
                    ),
                    priority="HIGH",
                    priority_rationale="Prototype pollution = bypass auth, RCE dans Node.js/Express",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="POST", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": "body",
                            "payload": payload,
                            "payload_type": "prototype_pollution",
                        },
                        description=f"Prototype pollution: {param.name}={payload[:50]}",
                    )],
                ))
        return hyps
