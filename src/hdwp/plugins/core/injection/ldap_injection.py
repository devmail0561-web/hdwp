# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""LDAPInjectionPlugin: détecte l'injection LDAP (CWE-90)."""
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

LDAP_PARAM_KEYWORDS = frozenset({
    "user", "username", "uid", "cn", "dn", "filter",
    "email", "login", "account", "group", "member",
})

LDAP_PAYLOADS = [
    "*",
    ")(uid=*))(|(uid=*",
    "admin)(&(password=*))",
    "*)(objectClass=*",
    ")(|(cn=*))",
]


class LDAPInjectionPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection LDAP."""

    @property
    def id(self) -> str:
        return "core.injection.ldap_injection"

    @property
    def name(self) -> str:
        return "LDAP Injection"

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
        return ["CWE-90"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        ldap_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in LDAP_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ]
        if not ldap_params:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement=(
                "LDAP queries must neutralize special characters to prevent injection"
            ),
            model_nodes=[p.id for p in ldap_params[:3]],
            inference_confidence=0.65,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        ldap_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in LDAP_PARAM_KEYWORDS)
            and p.type_inferred == "string"
        ][:3]
        if not ldap_params:
            return []
        hyps = []
        for param in ldap_params:
            for payload in LDAP_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' est vulnérable à l'injection LDAP",
                    priority="HIGH",
                    priority_rationale="LDAP injection = bypass auth, énumération annuaire",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": param.location,
                            "payload": payload,
                            "payload_type": "ldap",
                        },
                        description=f"LDAP injection: {param.name}={payload}",
                    )],
                ))
        return hyps
