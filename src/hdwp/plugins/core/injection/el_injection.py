# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""ELInjectionPlugin: Expression Language Injection (CWE-917) — Spring, Thymeleaf, JSP."""
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

EL_PARAM_KEYWORDS = frozenset({
    "name", "message", "template", "view", "expression",
    "lang", "locale", "format", "layout", "label",
})
EL_TECH_INDICATORS = ("spring", "thymeleaf", "jsp", "struts", "java", "tomcat", "jboss", "wildfly")

EL_PAYLOADS = [
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
]


class ELInjectionPlugin(HDWPPlugin):
    """Détecte les failles d'injection de langage d'expression (EL/SpEL/Thymeleaf)."""

    @property
    def id(self) -> str:
        return "core.injection.el_injection"

    @property
    def name(self) -> str:
        return "Expression Language (EL) Injection"

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
        return ["CWE-917"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        tech_stack = getattr(model, "tech_stack", [])
        uses_java = any(
            indicator in t.lower()
            for t in tech_stack
            for indicator in EL_TECH_INDICATORS
        )
        el_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in EL_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]
        if not uses_java and not el_params:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement="Expression language evaluation must not process user-controlled input",
            model_nodes=[p.id for p in el_params[:3]],
            inference_confidence=0.7,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        el_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in EL_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:3]
        if not el_params:
            return []
        hyps = []
        for param in el_params:
            for payload in EL_PAYLOADS[:3]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le paramètre '{param.name}' est vulnérable à l'injection EL"
                    ),
                    priority="HIGH",
                    priority_rationale="EL injection = RCE dans les frameworks Java (Spring, Struts, Thymeleaf)",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "el_injection",
                            "expected_result": "49" if "7*7" in payload else "",
                        },
                        description=f"EL injection: {param.name}={payload[:40]}",
                    )],
                ))
        return hyps
