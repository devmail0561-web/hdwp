# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""DeserializationPlugin: détecte la désérialisation non sécurisée (CWE-502)."""
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

DESER_PARAM_KEYWORDS = frozenset({
    "data", "object", "payload", "body", "serialized",
    "pickled", "state", "session_data",
})

# Marqueurs d'objets sérialisés pour détection (pas d'exploitation réelle)
DESER_DETECTION_PAYLOADS = [
    "rO0AB",                                        # Java serialized object magic bytes (base64)
    "gASV",                                         # Python pickle magic bytes (base64)
    '{"__class__": "test", "__module__": "os"}',    # Python class injection pattern
    'O:8:"stdClass":0:{}',                          # PHP serialized object marker
]


class DeserializationPlugin(HDWPPlugin):
    """Détecte la désérialisation non sécurisée d'objets."""

    @property
    def id(self) -> str:
        return "core.injection.deserialization"

    @property
    def name(self) -> str:
        return "Insecure Deserialization"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A08:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-502"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        deser_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in DESER_PARAM_KEYWORDS)
            and p.location == "body"
        ][:3]
        if not deser_params:
            return []

        hyps: list[Hypothesis] = []
        for param in deser_params:
            for payload in DESER_DETECTION_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' accepte des données sérialisées non validées",
                    priority="HIGH",
                    priority_rationale="Désérialisation non sécurisée = RCE potentielle",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="POST", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": "body",
                            "payload": payload,
                            "payload_type": "deserialization",
                        },
                        description=f"Deserialization probe: {param.name}",
                    )],
                ))
        return hyps
