# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
InfoDisclosurePlugin: détecte l'exposition de données sensibles dans les réponses.

Approche directe : déclencher des erreurs via des requêtes malformées (méthodes
invalides, paramètres manquants, types incorrects) et détecter les stack traces,
credentials, chemins système, ou informations de version dans les réponses.
"""
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

# Payloads conçus pour déclencher des erreurs révélatrices — pas des injections
_ERROR_TRIGGER_PAYLOADS = [
    ("__invalid__", "string", "Valeur string invalide pour champ typé"),
    ("null", "string", "Valeur null explicite"),
    ("-9999999999", "integer", "Integer hors-limites"),
]


class InfoDisclosurePlugin(HDWPPlugin):
    """Détecte l'exposition non-intentionnelle de données sensibles."""

    @property
    def id(self) -> str:
        return "core.information_flow.info_disclosure"

    @property
    def name(self) -> str:
        return "Information Disclosure"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021", "A02:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-200", "CWE-209", "CWE-312"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not model.endpoints:
            return []
        return [SecurityProperty(
            type=PropertyType.CONFIDENTIALITY,
            formal_statement=(
                "Responses must not expose stack traces, credentials, system paths, "
                "or version information in error messages"
            ),
            model_nodes=[ep.id for ep in model.endpoints[:5]],
            inference_confidence=0.5,
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for ep in model.endpoints[:5]:
            # Utiliser la première méthode observée (pas forcer GET)
            method = ep.methods[0] if ep.methods else "GET"
            # Cibler le premier paramètre numérique si disponible, sinon paramètre générique
            params = [p for p in model.parameters if p.id in ep.parameters]
            param = next((p for p in params if p.type_inferred == "integer"), None)
            param_name = param.name if param else "id"
            param_loc = param.location if param else "path"

            for payload, _type, desc in _ERROR_TRIGGER_PAYLOADS:
                hyps.append(Hypothesis(
                    source_plugin=self.id,
                    property_id="",
                    statement=(
                        f"L'endpoint '{ep.path}' expose des informations internes "
                        f"(stack trace, version, credentials) sur erreur"
                    ),
                    priority="MEDIUM",
                    priority_rationale="Information disclosure via messages d'erreur détaillés",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method=method, url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_loc,
                            "payload": payload,
                            "payload_type": "error_trigger",
                        },
                        description=f"{desc} sur {ep.path}",
                    )],
                ))
        return hyps[:5]
