# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Django DEBUG mode et information disclosure — activé si framework:django détecté."""
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


class DjangoDebugPlugin(HDWPPlugin):
    """Détecte les fuites d'information Django (DEBUG=True, tracebacks, etc.)."""

    @property
    def id(self) -> str:
        return "core.injection.django_debug"

    @property
    def name(self) -> str:
        return "Django Debug Mode Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "injection"

    def tech_stack_required(self) -> set[str]:
        return {"framework:django", "server:gunicorn", "server:uvicorn"}

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        # Si error_tech_signals contient "framework:django" → DEBUG=True probable
        if any("framework:django" in ep.error_tech_signals for ep in model.endpoints):
            return [SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.COHERENCE,
                formal_statement="Django DEBUG=True detected via error response leak",
                model_nodes=[ep.id for ep in model.endpoints if "framework:django" in ep.error_tech_signals],
                inference_confidence=0.92,
                source_observations=[],
            )]
        return [SecurityProperty(
            id=generate_id("PROP"),
            type=PropertyType.COHERENCE,
            formal_statement="Django application — potential DEBUG mode or traceback leak",
            model_nodes=[],
            inference_confidence=0.55,
            source_observations=[],
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        if not any(t in model.tech_stack for t in self.tech_stack_required()):
            return []
        hypotheses = []
        # Tenter de déclencher une traceback sur les endpoints existants
        for ep in model.endpoints[:5]:
            hypotheses.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=f"[Django Debug] {ep.path} — forcer une erreur pour obtenir un traceback",
                priority="MEDIUM",
                priority_rationale="Django DEBUG=True peut exposer settings, env vars, stack traces",
                required_experiments=[ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="GET", url=ep.path),
                    mutation_params={
                        "parameter_name": "__debug__",
                        "parameter_location": "query",
                        "payload": "1",
                        "payload_type": "django_debug",
                        "endpoint_path": ep.path,
                    },
                    description=f"Django debug probe: {ep.path}?__debug__=1",
                )],
            ))
        return hypotheses

    def register_mutations(self) -> list[dict]:
        return []
