# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.attack_graph.precondition_solver import PreconditionSolver
from hdwp.core.attack_graph.state import AttackState, AttackTransition, StateEffects
from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import HYPOTHESIS_GENERATED, PRECONDITION_MISSING


def _make_bus() -> AsyncEventBus:
    return AsyncEventBus()


def _make_transition(
    finding_id: str = "F-001",
    endpoint: str = "/api/users",
    preconditions: dict[str, set[str]] | None = None,
) -> AttackTransition:
    return AttackTransition(
        finding_id=finding_id,
        finding_type="BOLA",
        endpoint=endpoint,
        preconditions=preconditions or {},
        effects=StateEffects(grants_readable={endpoint}),
    )


@pytest.mark.asyncio
async def test_solve_returns_empty_when_no_preconditions_missing() -> None:
    bus = _make_bus()
    solver = PreconditionSolver(bus)
    state = AttackState(credentials_held={"any_authenticated"})
    transition = _make_transition(
        preconditions={"credentials_held": {"any_authenticated"}}
    )
    result = await solver.solve(state, transition)
    assert result == []


@pytest.mark.asyncio
async def test_solve_emits_precondition_missing_event() -> None:
    bus = _make_bus()
    collected: list = []
    bus.on(PRECONDITION_MISSING, lambda e: collected.append(e))
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        preconditions={"credentials_held": {"any_authenticated"}}
    )
    await solver.solve(state, transition)
    await bus.drain()

    assert len(collected) == 1


@pytest.mark.asyncio
async def test_solve_returns_hypotheses_for_missing_items() -> None:
    bus = _make_bus()
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        preconditions={"credentials_held": {"any_authenticated"}}
    )
    hyps = await solver.solve(state, transition)
    assert len(hyps) == 1
    assert "any_authenticated" in hyps[0].statement


@pytest.mark.asyncio
async def test_generated_hypotheses_have_precondition_probe_mutation_type() -> None:
    bus = _make_bus()
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        preconditions={"credentials_held": {"any_authenticated"}}
    )
    hyps = await solver.solve(state, transition)
    assert len(hyps) == 1
    assert hyps[0].required_experiments[0].mutation_type == "precondition_probe"


@pytest.mark.asyncio
async def test_generated_hypotheses_emitted_as_hypothesis_generated() -> None:
    bus = _make_bus()
    collected: list = []
    bus.on(HYPOTHESIS_GENERATED, lambda e: collected.append(e))
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        preconditions={"credentials_held": {"token_a"}}
    )
    await solver.solve(state, transition)
    await bus.drain()

    assert len(collected) == 1
    assert collected[0].payload["source_plugin"] == "precondition_solver"


@pytest.mark.asyncio
async def test_solve_multiple_missing_items_one_hypothesis_per_item() -> None:
    bus = _make_bus()
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        preconditions={
            "credentials_held": {"token_a", "token_b"},
            "privileges": {"elevated"},
        }
    )
    hyps = await solver.solve(state, transition)
    assert len(hyps) == 3
    mutation_types = {h.required_experiments[0].mutation_type for h in hyps}
    assert mutation_types == {"precondition_probe"}


@pytest.mark.asyncio
async def test_precondition_missing_payload_structure() -> None:
    bus = _make_bus()
    collected: list = []
    bus.on(PRECONDITION_MISSING, lambda e: collected.append(e))
    solver = PreconditionSolver(bus)

    state = AttackState()
    transition = _make_transition(
        finding_id="F-042",
        endpoint="/api/admin",
        preconditions={"privileges": {"admin"}},
    )
    await solver.solve(state, transition)
    await bus.drain()

    assert len(collected) == 1
    payload = collected[0].payload
    assert payload["finding_id"] == "F-042"
    assert payload["endpoint"] == "/api/admin"
    assert "privileges" in payload["missing"]
    assert "admin" in payload["missing"]["privileges"]
