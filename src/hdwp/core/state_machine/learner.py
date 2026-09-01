# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
StateMachineLearner: inférence de FSM par clustering de séquences d'observations.

Algorithme :
1. Grouper les observations par session_id → une séquence par session
2. Chaque observation devient un symbole (path_pattern, method, status_bucket)
3. Les états = symboles uniques observés
4. Les transitions = passages entre états consécutifs dans une séquence
5. Émettre fsm.updated quand la FSM change significativement

Note : algorithme simplifié (pas L*) — couvre les flux auth/checkout
mais pas les automates arbitrairement complexes.
"""
from __future__ import annotations

from collections import defaultdict

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FSM_UPDATED, OBSERVATION_RAW, HDWPEvent
from hdwp.core.model.schemas import (
    ApplicationFSM,
    FSMState,
    FSMTransition,
    NormalizedRequest,
    RawObservation,
    generate_id,
)
from hdwp.core.model.url_utils import normalize_url_path

log = structlog.get_logger()


def _status_bucket(status: int) -> str:
    if status < 300:
        return "2xx"
    if status < 400:
        return "3xx"
    if status in (401, 403):
        return "auth_error"
    if status < 500:
        return "4xx"
    return "5xx"


def _obs_to_symbol(obs: RawObservation) -> tuple[str, str, str]:
    """Convertit une observation en symbole (path_pattern, method, status_bucket)."""
    if obs.request is None or obs.response is None:
        return ("unknown", "GET", "0xx")
    path = normalize_url_path(obs.request.url)
    method = obs.request.method.upper()
    bucket = _status_bucket(obs.response.status_code)
    return (path, method, bucket)


class StateMachineLearner:
    """
    Apprend la FSM d'une application depuis les séquences d'observations.

    Souscrit à observation.raw.
    Publie fsm.updated quand la FSM change significativement (toutes les 10 obs).
    """

    def __init__(self, bus: AsyncEventBus) -> None:
        self._bus = bus
        # session_id → liste de symboles observés dans l'ordre
        self._sequences: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        self._fsm: ApplicationFSM | None = None
        self._obs_count = 0
        bus.on(OBSERVATION_RAW, self._on_observation)

    async def _on_observation(self, event: HDWPEvent) -> None:
        data = event.payload
        obs = RawObservation.model_validate(data) if isinstance(data, dict) else data
        symbol = _obs_to_symbol(obs)
        self._sequences[obs.session_id].append(symbol)
        self._obs_count += 1

        if self._obs_count % 10 == 0:
            new_fsm = self._build_fsm()
            if self._fsm_changed(new_fsm):
                self._fsm = new_fsm
                await self._bus.emit(
                    FSM_UPDATED, new_fsm.model_dump(), source="state_machine_learner"
                )
                log.info(
                    "fsm.updated",
                    states=len(new_fsm.states),
                    transitions=len(new_fsm.transitions),
                )

    def _build_fsm(self) -> ApplicationFSM:
        """Construit la FSM depuis les séquences observées."""
        all_symbols: set[tuple[str, str, str]] = set()
        for seq in self._sequences.values():
            all_symbols.update(seq)

        # État initial
        initial = FSMState(
            id=generate_id("FSM-S"),
            label="initial",
            observable_conditions=["No requests sent"],
        )
        states: list[FSMState] = [initial]
        symbol_to_state_id: dict[tuple[str, str, str], str] = {}

        for sym in all_symbols:
            path, method, status = sym
            state = FSMState(
                id=generate_id("FSM-S"),
                label=f"{method}:{path}:{status}",
                observable_conditions=[f"{method} {path} returned {status}"],
            )
            states.append(state)
            symbol_to_state_id[sym] = state.id

        # Transitions depuis les séquences
        transitions: list[FSMTransition] = []
        seen: set[tuple[str, str]] = set()

        for seq in self._sequences.values():
            if not seq:
                continue
            prev_id = initial.id
            for sym in seq:
                curr_id = symbol_to_state_id.get(sym, initial.id)
                key = (prev_id, curr_id)
                if key not in seen:
                    seen.add(key)
                    path, method, _ = sym
                    transitions.append(FSMTransition(
                        from_state=prev_id,
                        to_state=curr_id,
                        trigger=NormalizedRequest(method=method, url=path),
                    ))
                prev_id = curr_id

        confidence = min(0.9, len(self._sequences) / 10.0)

        return ApplicationFSM(
            id=generate_id("FSM"),
            states=states,
            transitions=transitions,
            initial_state=initial.id,
            confidence=confidence,
        )

    def _fsm_changed(self, new_fsm: ApplicationFSM) -> bool:
        if self._fsm is None:
            return bool(new_fsm.states)
        return (
            len(new_fsm.states) != len(self._fsm.states)
            or len(new_fsm.transitions) != len(self._fsm.transitions)
        )

    @property
    def current_fsm(self) -> ApplicationFSM | None:
        return self._fsm
