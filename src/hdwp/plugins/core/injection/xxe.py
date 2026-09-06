# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""XXEPlugin: détecte les vulnérabilités XML External Entity (CWE-611)."""
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

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
]


class XXEPlugin(HDWPPlugin):
    """Détecte les failles XML External Entity Injection."""

    @property
    def id(self) -> str:
        return "core.injection.xxe"

    @property
    def name(self) -> str:
        return "XML External Entity (XXE) Injection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A05:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-611"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        xml_endpoints = [
            ep for ep in model.endpoints
            if getattr(ep, "accepts_xml", False)
            or "xml" in (getattr(ep, "response_content_type", "") or "").lower()
        ]
        if not xml_endpoints:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement="XML parsers must disable external entity processing (XXE)",
            model_nodes=[ep.id for ep in xml_endpoints[:3]],
            inference_confidence=0.8,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        xml_endpoints = [ep for ep in model.endpoints if getattr(ep, "accepts_xml", False)]
        xml_params = [
            p for p in model.parameters
            if getattr(p, "semantic", None) == "xml_input"
            or "xml" in p.name.lower()
            or "soap" in p.name.lower()
        ]
        if not xml_endpoints and not xml_params:
            return []

        hyps: list[Hypothesis] = []
        targets = xml_endpoints[:3] or model.endpoints[:2]
        for ep in targets:
            method = next((m for m in ep.methods if m in ("POST", "PUT")), ep.methods[0] if ep.methods else "POST")
            for payload in XXE_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"L'endpoint '{ep.path}' est vulnérable à XXE — lecture fichiers système",
                    priority="HIGH",
                    priority_rationale="XXE = lecture fichiers arbitraires + SSRF interne",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method=method, url=""),
                        mutation_params={
                            "parameter_name": "body",
                            "parameter_location": "body",
                            "payload": payload,
                            "payload_type": "xxe",
                        },
                        description=f"XXE payload sur {ep.path}",
                    )],
                ))
        return hyps
