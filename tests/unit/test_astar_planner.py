# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.attack_graph.goals import GoalDefinition, GoalType
from hdwp.core.attack_graph.planner import AttackGraphPlanner
from hdwp.core.attack_graph.state import AttackState, AttackTransition, StateEffects
from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDINGS_CORRELATED, GOAL_REACHED
from hdwp.core.model.schemas import ConfidenceScore, Finding


def _make_bus() -> AsyncEventBus:
    return AsyncEventBus()


def _make_planner(bus: AsyncEventBus | None = None) -> AttackGraphPlanner:
    b = bus or _make_bus()
    return AttackGraphPlanner(bus=b)


def _make_finding(
    id: str = "F-001",
    property_type: str = "BOLA",
    confidence: float = 0.9,
    endpoint: str = "/api/users/{id}",
) -> Finding:
    return Finding(
        id=id,
        hypothesis_id="HYP-test",
        property_id="PROP-test",
        property_type=property_type,
        status="CONFIRMED",
        owasp_category="API1:2023",
        cwe_id="CWE-639",
        severity="HIGH",
        confidence=confidence,
        confidence_breakdown=ConfidenceScore(overall=confidence),
        affected_endpoints=[endpoint],
        proof={"reproduction_steps": ["test step"]},
        remediation_hint="Fix it",
    )


def _make_simple_goal() -> GoalDefinition:
    return GoalDefinition(
        goal_type=GoalType.DATA_EXFILTRATION,
        required_state={"assets_readable": {"sensitive_data"}},
        description="Read sensitive data",
    )


def _make_transition(
    finding_id: str = "F-001",
    endpoint: str = "/api/data",
    grants_readable: set[str] | None = None,
    grants_privileges: set[str] | None = None,
    cost: float = 0.5,
    preconditions: dict[str, set[str]] | None = None,
) -> AttackTransition:
    return AttackTransition(
        finding_id=finding_id,
        finding_type="test",
        endpoint=endpoint,
        preconditions=preconditions or {},
        effects=StateEffects(
            grants_readable=grants_readable or set(),
            grants_privileges=grants_privileges or set(),
        ),
        cost=cost,
    )


def test_plan_returns_none_when_no_transitions() -> None:
    planner = _make_planner()
    result = planner.plan(goal=_make_simple_goal())
    assert result is None


def test_plan_finds_path_single_transition() -> None:
    planner = _make_planner()
    planner._transitions = [
        _make_transition(grants_readable={"sensitive_data"}, cost=0.2),
    ]
    planner._goals = [_make_simple_goal()]

    path = planner.plan(goal=_make_simple_goal())
    assert path is not None
    assert len(path) == 1
    assert path[0].finding_id == "F-001"


def test_plan_finds_optimal_path() -> None:
    planner = _make_planner()
    expensive = _make_transition(
        finding_id="F-EXP",
        grants_readable={"sensitive_data"},
        cost=0.9,
    )
    cheap = _make_transition(
        finding_id="F-CHEAP",
        grants_readable={"sensitive_data"},
        cost=0.1,
    )
    planner._transitions = [expensive, cheap]

    path = planner.plan(goal=_make_simple_goal())
    assert path is not None
    assert len(path) == 1
    assert path[0].finding_id == "F-CHEAP"


def test_plan_returns_none_when_goal_unreachable() -> None:
    planner = _make_planner()
    planner._transitions = [
        _make_transition(grants_readable={"other_data"}, cost=0.3),
    ]

    path = planner.plan(goal=_make_simple_goal())
    assert path is None


def test_has_pending_chains_false_with_fewer_than_two() -> None:
    planner = _make_planner()
    assert planner.has_pending_chains() is False
    planner._confirmed_findings.append(_make_finding())
    assert planner.has_pending_chains() is False


def test_has_pending_chains_true_with_two_or_more() -> None:
    planner = _make_planner()
    planner._confirmed_findings.append(_make_finding(id="F-001"))
    planner._confirmed_findings.append(_make_finding(id="F-002"))
    assert planner.has_pending_chains() is True


def test_heuristic_admissible() -> None:
    planner = _make_planner()
    goal = GoalDefinition(
        goal_type=GoalType.PRIVILEGE_ESCALATION,
        required_state={"privileges": {"elevated", "admin"}},
    )
    state = AttackState(privileges={"elevated"})
    h = planner._heuristic(state, goal)
    assert h == 1.0
    assert h <= 1.0

    full_state = AttackState(privileges={"elevated", "admin"})
    h_full = planner._heuristic(full_state, goal)
    assert h_full == 0.0


@pytest.mark.asyncio
async def test_plan_and_execute_emits_findings_correlated() -> None:
    bus = _make_bus()
    planner = _make_planner(bus)

    planner._transitions = [
        _make_transition(grants_readable={"sensitive_data"}, cost=0.1),
    ]
    planner._goals = [_make_simple_goal()]

    collected: list = []
    bus.on(FINDINGS_CORRELATED, lambda e: collected.append(e))

    await planner.plan_and_execute(exp_engine=None)
    await bus.drain()

    assert len(collected) == 1
    assert collected[0].payload["status"] == "success"


@pytest.mark.asyncio
async def test_plan_and_execute_emits_goal_reached() -> None:
    bus = _make_bus()
    planner = _make_planner(bus)

    planner._transitions = [
        _make_transition(grants_readable={"sensitive_data"}, cost=0.1),
    ]
    planner._goals = [_make_simple_goal()]

    reached: list = []
    bus.on(GOAL_REACHED, lambda e: reached.append(e))

    await planner.plan_and_execute(exp_engine=None)
    await bus.drain()

    assert len(reached) == 1
    assert reached[0].payload["goal_type"] == "DATA_EXFILTRATION"
    assert reached[0].payload["plan_steps"] == 1


@pytest.mark.asyncio
async def test_discover_chains_returns_plan_summaries() -> None:
    planner = _make_planner()
    planner._transitions = [
        _make_transition(grants_readable={"sensitive_data"}, cost=0.2),
    ]
    planner._goals = [_make_simple_goal()]

    plans = await planner.discover_chains()
    assert len(plans) >= 1
    plan = plans[0]
    assert plan["goal_type"] == "DATA_EXFILTRATION"
    assert plan["steps"] == 1
    assert "finding_ids" in plan
    assert plan["finding_ids"] == ["F-001"]
