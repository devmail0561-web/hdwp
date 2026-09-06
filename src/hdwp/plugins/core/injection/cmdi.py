# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CMDiPlugin: détecte les vulnérabilités d'injection de commandes OS.

Réutilise la mutation field_injection avec payload_type='cmdi'.
Détection via InjectionOracle.assess_cmdi() existant.
"""
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

CMDI_PARAM_KEYWORDS = frozenset({
    "cmd", "exec", "command", "run", "ping", "host", "ip",
    "query", "shell", "execute", "process", "system",
})

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
]


class CMDiPlugin(HDWPPlugin):
    """Détecte les vulnérabilités d'injection de commandes OS."""

    @property
    def id(self) -> str:
        return "core.injection.cmdi"

    @property
    def name(self) -> str:
        return "Command Injection Detection"

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
        return ["CWE-78"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        cmdi_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in CMDI_PARAM_KEYWORDS)
            and p.type_inferred in ("string",)
        ]
        if not cmdi_params:
            return []
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement="System commands must not be constructed from user input",
                model_nodes=[p.id for p in cmdi_params[:5]],
                inference_confidence=0.8,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        candidates = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in CMDI_PARAM_KEYWORDS)
            and p.type_inferred in ("string",)
        ][:5]

        hypotheses = []
        for param in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                        "payload": payload,
                        "payload_type": "cmdi",
                    },
                    description=f"CMDi test: {param.name}={payload}",
                )
                for payload in CMDI_PAYLOADS[:3]
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' est vulnérable à l'injection de commandes",
                    priority="HIGH",
                    priority_rationale="CMDi permet exécution de commandes arbitraires sur le serveur",
                    required_experiments=experiments,
                )
            )
        return hypotheses
