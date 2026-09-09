# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""XPathInjectionPlugin: détecte l'injection XPath (CWE-643)."""
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

XPATH_PARAM_KEYWORDS = frozenset({
    "user", "username", "login", "search", "query", "filter",
    "name", "id", "item", "node", "element",
})

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or 1=1 or ''='",
    "x' or name()='username' or 'x'='y",
    "' or count(/*)>0 or ''='",
    "admin' or '1'='1",
]


class XPathInjectionPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection XPath."""

    @property
    def id(self) -> str:
        return "core.injection.xpath_injection"

    @property
    def name(self) -> str:
        return "XPath Injection"

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
        return ["CWE-643"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        tech_stack = getattr(model, "tech_stack", [])
        uses_xml = any(
            "xml" in t.lower() or "xpath" in t.lower() or "xquery" in t.lower()
            for t in tech_stack
        )
        xml_endpoints = [ep for ep in model.endpoints if getattr(ep, "accepts_xml", False)]
        if not uses_xml and not xml_endpoints:
            return []
        xpath_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in XPATH_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]
        if not xpath_params:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement="XPath queries must sanitize user input to prevent injection",
            model_nodes=[p.id for p in xpath_params[:3]],
            inference_confidence=0.6,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        xpath_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in XPATH_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:3]
        if not xpath_params:
            return []
        hyps = []
        for param in xpath_params:
            for payload in XPATH_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' est vulnérable à l'injection XPath",
                    priority="MEDIUM",
                    priority_rationale="XPath injection = bypass auth sur apps XML, extraction données",
                    required_experiments=[ExperimentSpec(
                        mutation_type="xpath_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "xpath",
                        },
                        description=f"XPath injection: {param.name}={payload}",
                    )],
                ))
        return hyps
