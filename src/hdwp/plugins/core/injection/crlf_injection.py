# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""CRLFPlugin: détecte l'injection de headers HTTP via CRLF (CWE-113)."""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    SecurityProperty,
)
from hdwp.plugins.base import HDWPPlugin

CRLF_PAYLOADS = [
    "foo\r\nX-Injected: hdwp-test",
    "foo%0d%0aX-Injected: hdwp-test",
    "foo%0aSet-Cookie: hdwp-session=injected",
]
CRLF_PARAM_KEYWORDS = frozenset({
    "name", "url", "redirect", "next", "header", "location",
    "title", "host", "lang", "locale",
})


class CRLFPlugin(HDWPPlugin):
    """Détecte l'injection CRLF dans les headers HTTP."""

    @property
    def id(self) -> str:
        return "core.injection.crlf"

    @property
    def name(self) -> str:
        return "CRLF / Header Injection"

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
        return ["CWE-113"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in CRLF_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:3]
        if not candidates:
            return []

        hyps: list[Hypothesis] = []
        for param in candidates:
            for payload in CRLF_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' permet l'injection de headers HTTP via CRLF",
                    priority="MEDIUM",
                    priority_rationale="CRLF injection permet cookie injection, session fixation, cache poisoning",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "crlf",
                        },
                        description=f"CRLF injection: {param.name}={payload[:30]}",
                    )],
                ))
        return hyps
