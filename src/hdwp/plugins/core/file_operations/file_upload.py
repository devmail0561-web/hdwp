# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""FileUploadPlugin: détecte l'upload de fichiers dangereux (CWE-434)."""
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

UPLOAD_PARAM_KEYWORDS = frozenset({
    "file", "upload", "attachment", "image", "photo",
    "document", "avatar", "media", "asset", "blob",
})

DANGEROUS_FILE_PAYLOADS = [
    ("evil.php", "application/x-php", "PHP webshell upload"),
    ("evil.jsp", "application/java-archive", "JSP webshell upload"),
    ("evil.sh", "application/x-sh", "Shell script upload"),
    ("../../evil.txt", "text/plain", "Path traversal dans nom de fichier"),
]


class FileUploadPlugin(HDWPPlugin):
    """Détecte les failles d'upload de fichiers non restreint."""

    @property
    def id(self) -> str:
        return "core.file_operations.file_upload"

    @property
    def name(self) -> str:
        return "Unrestricted File Upload"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "file_operations"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A04:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-434"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        upload_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in UPLOAD_PARAM_KEYWORDS)
        ]
        if not upload_params:
            return []
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.INTEGRITY,
            formal_statement=(
                "File uploads must validate type, content, and reject dangerous extensions"
            ),
            model_nodes=[p.id for p in upload_params[:3]],
            inference_confidence=0.75,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        upload_params = [
            p for p in model.parameters
            if any(kw in p.name.lower() for kw in UPLOAD_PARAM_KEYWORDS)
        ][:3]
        if not upload_params:
            return []
        hyps = []
        for param in upload_params:
            for filename, content_type, desc in DANGEROUS_FILE_PAYLOADS[:2]:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"Le paramètre '{param.name}' accepte des fichiers "
                        f"de type dangereux ({filename})"
                    ),
                    priority="HIGH",
                    priority_rationale="Upload non restreint = RCE via webshell",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="POST", url=""),
                        mutation_params={
                            "parameter_name": param.name,
                            "parameter_location": "body",
                            "payload": filename,
                            "payload_type": "file_upload",
                            "content_type": content_type,
                        },
                        description=f"{desc}: {param.name}={filename}",
                    )],
                ))
        return hyps
