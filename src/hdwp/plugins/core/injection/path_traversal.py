# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
PathTraversalPlugin: détecte les vulnérabilités de traversée de chemin / LFI.
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

PATH_PARAM_KEYWORDS = frozenset({
    "file", "path", "filename", "include", "page", "template",
    "dir", "folder", "document", "resource", "load", "read",
})

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%5c..%5cwindows%5cwin.ini",
]


class PathTraversalPlugin(HDWPPlugin):
    """Détecte les vulnérabilités de traversée de chemin (LFI/path traversal)."""

    @property
    def id(self) -> str:
        return "core.injection.path_traversal"

    @property
    def name(self) -> str:
        return "Path Traversal / LFI Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-22"]

    @staticmethod
    def _candidates(model: ApplicationModelData) -> list:
        # Priorité : signal sémantique (modèle a déjà identifié file_path)
        semantic = [p for p in model.parameters if getattr(p, 'semantic', None) == "file_path"]
        if semantic:
            return semantic[:5]
        # Fallback : keyword matching
        return [p for p in model.parameters
                if any(kw in p.name.lower() for kw in PATH_PARAM_KEYWORDS)
                and p.type_inferred == "string"][:5]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        candidates = self._candidates(model)
        if not candidates:
            return []
        # Confidence élevée si semantic détecté par le modèle (signal fort)
        confidence = 0.9 if any(getattr(p, 'semantic', None) == "file_path" for p in candidates) else 0.8
        return [
            SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.INTEGRITY,
                formal_statement="file path parameters must be validated against directory traversal",
                model_nodes=[p.id for p in candidates[:5]],
                inference_confidence=confidence,
                source_observations=[],
            )
        ]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        candidates = self._candidates(model)

        hypotheses = []
        for param in candidates:
            experiments = [
                ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=""),
                    mutation_params={
                        "payload": payload,
                        "payload_type": "path_traversal",
                        "parameter_name": param.name,
                        "parameter_location": param.location,
                    },
                    description=f"Path traversal: {param.name}={payload[:30]}",
                )
                for payload in PATH_TRAVERSAL_PAYLOADS
            ]
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=f"Le paramètre '{param.name}' est vulnérable à la traversée de chemin",
                    priority="HIGH",
                    priority_rationale="LFI permet la lecture de fichiers système sensibles",
                    required_experiments=experiments,
                )
            )
        return hypotheses
