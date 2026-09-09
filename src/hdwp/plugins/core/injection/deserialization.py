# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""DeserializationPlugin: détecte la désérialisation non sécurisée (CWE-502)."""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
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


# Phase 1: Mutation custom Deserialization avec magic bytes detection

def register_deserialization_mutations() -> None:
    """Enregistre mutation custom deserialization_probe dans MutationRegistry.

    Phase 1 optionnel: Améliore la détection en cherchant magic bytes
    Java (\xac\xed), Python (\x80\x03), PHP (O:) dans les réponses.
    """
    from hdwp.core.mutation_registry import register_mutation

    MAGIC_BYTES = {
        "java": b"\xac\xed",      # Java serialized object
        "python": b"\x80\x03",    # Python pickle protocol 3
        "php": b"O:",             # PHP serialized object
    }

    def assess_deserialization_probe(baseline, experiment, diff):
        """Assess deserialization par détection magic bytes."""
        from hdwp.core.oracle.violation_oracle import ViolationAssessment, ConfidenceLevel

        body = experiment.response_received.body
        if body is None:
            body_bytes = b""
        elif isinstance(body, str):
            body_bytes = body.encode()
        else:
            body_bytes = body

        # Détecter magic bytes dans réponse
        for lang, magic in MAGIC_BYTES.items():
            if magic in body_bytes:
                return ViolationAssessment(
                    violated=True,
                    confidence=ConfidenceLevel.HIGH,
                    verdict=f"Deserialization detected: {lang} magic bytes found",
                    evidence=[f"Magic bytes {magic.hex()} found in response"],
                )

        # Fallback vers assess_field_injection
        from hdwp.core.oracle.violation_oracle import _assess_field_injection
        return _assess_field_injection(baseline, experiment, diff)

    register_mutation(
        name="deserialization_probe",
        owasp_category="A08:2021",
        cwe_id="CWE-502",
        remediation="Avoid deserializing untrusted data; use safe serialization formats",
        assess_violation=assess_deserialization_probe,
    )


# Auto-registration au chargement du module
try:
    register_deserialization_mutations()
except Exception:
    # Ignore si MutationRegistry pas encore initialisé
    pass
