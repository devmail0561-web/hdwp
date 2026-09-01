# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
StateInference: inférence de propriétés d'état depuis le modèle applicatif.

Deux sources :
1. FSM apprise (model.fsm) — propriétés sur les séquences d'états réels
2. Pattern de nommage — step/stage/wizard dans les chemins d'endpoints
"""
from __future__ import annotations

import re

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)

_STEP_PATTERN = re.compile(
    r"(step|stage|phase|wizard)[/_-]?\d|/\d+(/|$)", re.IGNORECASE
)


class StateInference:
    """Infers state-transition properties from the application model."""

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []

        # Source 1 : FSM apprise par StateMachineLearner
        if model.fsm is not None and len(model.fsm.states) >= 3:
            non_initial = [s for s in model.fsm.states if s.id != model.fsm.initial_state]
            if non_initial:
                props.append(SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.STATE,
                    formal_statement=(
                        f"FSM: reachable({non_initial[0].label}) => "
                        "all predecessors visited in correct order"
                    ),
                    model_nodes=[s.id for s in model.fsm.states[:3]],
                    inference_confidence=model.fsm.confidence,
                    source_observations=[],
                ))

        # Source 2 : patterns de nommage (step1/step2/wizard)
        step_endpoints = [ep for ep in model.endpoints if _STEP_PATTERN.search(ep.path)]
        if len(step_endpoints) >= 2:
            props.append(SecurityProperty(
                id=generate_id("PROP"),
                type=PropertyType.STATE,
                formal_statement=(
                    "State sequence enforced: steps must be followed in order "
                    f"({[ep.path for ep in step_endpoints[:3]]})"
                ),
                model_nodes=[ep.id for ep in step_endpoints[:3]],
                inference_confidence=0.5,
                source_observations=[],
            ))

        return props
