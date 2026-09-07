# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
AmbiguityResolver: génère des expériences de suivi ciblées pour lever les verdicts AMBIGUOUS.

Abonné à hypothesis.ambiguous, il examine le SemanticDiff et construit
de nouveaux ExperimentSpec de désambiguïsation, puis émet hypothesis.generated
pour relancer le cycle oracle.

Garde : disambiguation_attempts ≤ MAX_DISAMBIGUATION_ATTEMPTS par hypothèse.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import HYPOTHESIS_AMBIGUOUS, HYPOTHESIS_GENERATED
from hdwp.core.model.schemas import (
    ExperimentSpec,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    SemanticDiff,
    generate_id,
)

if TYPE_CHECKING:
    from hdwp.store.repository import Repository

log = structlog.get_logger()

MAX_DISAMBIGUATION_ATTEMPTS = 2


class AmbiguityResolver:
    """Abonné au bus, génère des expériences de désambiguïsation sur verdict AMBIGUOUS."""

    def __init__(self, bus: AsyncEventBus, repository: Repository) -> None:
        self._bus = bus
        self._repo = repository
        bus.on(HYPOTHESIS_AMBIGUOUS, self._on_ambiguous)

    async def _on_ambiguous(self, event: Any) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        hyp_id: str = payload.get("hypothesis_id", "")
        mutation_type: str = payload.get("mutation_type", "")
        diff_data: dict | None = payload.get("diff")
        baseline_spec_data: dict | None = payload.get("baseline_spec")

        if not hyp_id or diff_data is None:
            return

        # Charger l'hypothèse pour vérifier le garde
        hyp = await self._repo.get_hypothesis(hyp_id)
        if hyp is None:
            return
        if hyp.disambiguation_attempts >= MAX_DISAMBIGUATION_ATTEMPTS:
            log.info(
                "ambiguity_resolver.max_attempts_reached",
                hypothesis_id=hyp_id,
                attempts=hyp.disambiguation_attempts,
            )
            return

        try:
            diff = SemanticDiff.model_validate(diff_data)
        except Exception:
            return

        baseline_spec = None
        if baseline_spec_data:
            try:
                baseline_spec = ExperimentSpec.model_validate(baseline_spec_data)
            except Exception:
                pass

        followup_specs = self._build_disambiguation_specs(diff, mutation_type, baseline_spec)
        if not followup_specs:
            log.debug("ambiguity_resolver.no_followup", hypothesis_id=hyp_id)
            return

        # Créer une nouvelle hypothèse de désambiguïsation
        disambiguation_hyp = Hypothesis(
            id=generate_id("HYP"),
            status=HypothesisStatus.PENDING,
            source_plugin="ambiguity_resolver",
            property_id=hyp.property_id,
            statement=f"[DISAMBIG] {hyp.statement[:120]}",
            priority="HIGH",
            priority_rationale="Désambiguïsation post-AMBIGUOUS",
            required_experiments=followup_specs,
            disambiguation_attempts=hyp.disambiguation_attempts + 1,
        )

        try:
            await self._repo.save_hypothesis(disambiguation_hyp)
        except Exception:
            pass

        await self._bus.emit(
            HYPOTHESIS_GENERATED,
            disambiguation_hyp.model_dump(),
            source="ambiguity_resolver",
        )
        log.info(
            "ambiguity_resolver.followup_generated",
            hypothesis_id=hyp_id,
            new_hypothesis_id=disambiguation_hyp.id,
            mutation_type=mutation_type,
            n_specs=len(followup_specs),
        )

    def _build_disambiguation_specs(
        self,
        diff: SemanticDiff,
        mutation_type: str,
        baseline_spec: ExperimentSpec | None,
    ) -> list[ExperimentSpec]:
        """Sélectionne la stratégie de désambiguïsation selon les champs du diff."""
        specs: list[ExperimentSpec] = []

        param_name = ""
        param_loc = "query"
        endpoint = ""
        if baseline_spec is not None:
            param_name = baseline_spec.mutation_params.get("parameter_name", "")
            param_loc = baseline_spec.mutation_params.get("parameter_location", "query")
            endpoint = (
                baseline_spec.mutation_params.get("endpoint_path", "")
                or baseline_spec.mutation_params.get("target_endpoint", "")
            )

        # ── Stratégie 1 : pas de champs d'identité → probe avec une sentinelle ──
        if diff.data_identity_score is None and diff.behavioral_difference and mutation_type == "identity_swap":
            sentinel = f"probe-{uuid.uuid4().hex[:8]}"
            specs.append(ExperimentSpec(
                mutation_type="field_injection",
                base_request=NormalizedRequest(method="", url=""),
                mutation_params={
                    "parameter_name": param_name or "user_id",
                    "parameter_location": param_loc,
                    "payload": sentinel,
                    "payload_type": "identity_probe",
                    "endpoint_path": endpoint,
                    "_disambiguation": "no_identity_fields",
                },
                description="Désambiguïsation : injection sentinelle pour détecter les champs identité",
            ))

        # ── Stratégie 2 : ratio taille ≥ 2.0 → re-sonder avec IDs adjacents ──
        if (
            diff.response_size_ratio is not None
            and diff.response_size_ratio >= 2.0
            and mutation_type == "object_ref_change"
            and param_name
        ):
            for probe_val in ("2", "3", "100"):
                specs.append(ExperimentSpec(
                    mutation_type="object_ref_change",
                    base_request=NormalizedRequest(method="", url=""),
                    mutation_params={
                        "parameter_name": param_name,
                        "parameter_location": param_loc,
                        "target_value": probe_val,
                        "endpoint_path": endpoint,
                        "_disambiguation": "size_ratio_probe",
                    },
                    description=f"Désambiguïsation : re-sonde objet {probe_val} (size_ratio={diff.response_size_ratio:.1f})",
                ))

        # ── Stratégie 3 : champs suspects → cibler ces champs spécifiquement ──
        if diff.suspicious_fields and param_name:
            for field in diff.suspicious_fields[:2]:
                specs.append(ExperimentSpec(
                    mutation_type="field_injection",
                    base_request=NormalizedRequest(method="", url=""),
                    mutation_params={
                        "parameter_name": field,
                        "parameter_location": "body",
                        "payload": "probe-suspicious",
                        "payload_type": "probe",
                        "endpoint_path": endpoint,
                        "_disambiguation": "suspicious_field",
                    },
                    description=f"Désambiguïsation : cibler le champ suspect '{field}'",
                ))

        # ── Stratégie 4 : body vide sur 2xx → sonder d'autres IDs ──
        if (
            not diff.structural_difference
            and not diff.behavioral_difference
            and mutation_type == "object_ref_change"
            and param_name
        ):
            specs.append(ExperimentSpec(
                mutation_type="object_ref_change",
                base_request=NormalizedRequest(method="", url=""),
                mutation_params={
                    "parameter_name": param_name,
                    "parameter_location": param_loc,
                    "target_value": "42",
                    "endpoint_path": endpoint,
                    "_disambiguation": "empty_body_retry",
                },
                description="Désambiguïsation : corps vide — re-sonde avec ID=42",
            ))

        return specs
