# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import heapq
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from hdwp.core.attack_graph.goals import BUILTIN_GOALS, GoalDefinition
from hdwp.core.attack_graph.precondition_solver import PreconditionSolver
from hdwp.core.attack_graph.state import AttackState, AttackTransition
from hdwp.core.bus.events import (
    FINDING_CONFIRMED,
    FINDINGS_CORRELATED,
    GOAL_REACHED,
    HDWPEvent,
)
from hdwp.core.model.schemas import ChainSpec, ChainStep, Finding, generate_id

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.store.repository import Repository

logger = structlog.get_logger()


@dataclass(order=True)
class _AStarNode:
    f_cost: float
    g_cost: float = field(compare=False)
    state: AttackState = field(compare=False)
    path: list[AttackTransition] = field(compare=False, default_factory=list)


class AttackGraphPlanner:
    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable | None = None,
        flow_map_accessor: Callable | None = None,
        repository: Repository | None = None,
        target_url: str = "",
        roles: list | None = None,
        session_id: str = "",
    ) -> None:
        self._bus = bus
        self._model_accessor = model_accessor
        self._flow_map_accessor = flow_map_accessor
        self._repository = repository
        self._target_url = target_url
        self._roles = roles or []
        self._session_id = session_id

        self._confirmed_findings: list[Finding] = []
        self._transitions: list[AttackTransition] = []
        self._precondition_solver = PreconditionSolver(bus)
        self._goals: list[GoalDefinition] = list(BUILTIN_GOALS.values())

        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)

    async def _on_finding_confirmed(self, event: HDWPEvent) -> None:
        try:
            finding = Finding.model_validate(event.payload)
            self._confirmed_findings.append(finding)
            transition = AttackTransition.from_finding(event.payload)
            self._transitions.append(transition)
        except Exception:
            logger.warning("attack_graph.finding_parse_error", exc_info=True)

    def has_pending_chains(self) -> bool:
        return len(self._confirmed_findings) >= 2

    def _heuristic(self, state: AttackState, goal: GoalDefinition) -> float:
        return float(state.missing_for(goal.required_state))

    def plan(
        self,
        initial_state: AttackState | None = None,
        goal: GoalDefinition | None = None,
    ) -> list[AttackTransition] | None:
        if not self._transitions:
            return None

        state = initial_state or AttackState()
        if goal is None:
            goal = self._select_best_goal(state)
            if goal is None:
                return None

        start = _AStarNode(
            f_cost=self._heuristic(state, goal),
            g_cost=0.0,
            state=state,
            path=[],
        )

        open_set: list[_AStarNode] = [start]
        visited: set[frozenset] = set()

        while open_set:
            current = heapq.heappop(open_set)

            state_key = self._state_key(current.state)
            if state_key in visited:
                continue
            visited.add(state_key)

            if goal.is_reached({
                "assets_readable": current.state.assets_readable,
                "assets_writable": current.state.assets_writable,
                "credentials_held": current.state.credentials_held,
                "privileges": current.state.privileges,
            }):
                return current.path

            for transition in self._transitions:
                if transition.finding_id in [t.finding_id for t in current.path]:
                    continue

                if not current.state.satisfies(transition.preconditions):
                    continue

                new_state = current.state.apply_effects(transition.effects)
                new_path = current.path + [transition]
                g_cost = current.g_cost + transition.cost
                h_cost = self._heuristic(new_state, goal)
                f_cost = g_cost + h_cost

                heapq.heappush(open_set, _AStarNode(
                    f_cost=f_cost,
                    g_cost=g_cost,
                    state=new_state,
                    path=new_path,
                ))

        return None

    def _select_best_goal(self, state: AttackState) -> GoalDefinition | None:
        best: GoalDefinition | None = None
        best_missing = float("inf")
        for goal in self._goals:
            m = state.missing_for(goal.required_state)
            if m < best_missing:
                best_missing = m
                best = goal
        return best

    def _state_key(self, state: AttackState) -> frozenset:
        return frozenset(
            list(state.assets_readable)
            + list(state.assets_writable)
            + list(state.credentials_held)
            + list(state.privileges)
        )

    async def plan_and_execute(self, exp_engine: Any) -> list[ChainSpec]:
        if not self._transitions:
            return []

        executed_specs: list[ChainSpec] = []

        for goal in self._goals:
            plan = self.plan(goal=goal)
            if not plan:
                continue

            spec = self._plan_to_chain_spec(plan, goal)
            logger.info(
                "attack_graph.executing",
                goal=goal.goal_type.value,
                steps=len(plan),
            )

            success, proof = await self._execute_plan(plan, exp_engine)

            if success:
                await self._save_chain_finding(spec, proof)
                await self._bus.emit(
                    FINDINGS_CORRELATED,
                    {
                        "chain_type": spec.chain_type,
                        "description": spec.description,
                        "trigger_finding_ids": spec.precondition_finding_ids,
                        "status": "success",
                    },
                    source="attack_graph_planner",
                )
                await self._bus.emit(
                    GOAL_REACHED,
                    {
                        "goal_type": goal.goal_type.value,
                        "plan_steps": len(plan),
                        "total_cost": sum(t.cost for t in plan),
                    },
                    source="attack_graph_planner",
                )
                executed_specs.append(spec)
                logger.info("attack_graph.goal_reached", goal=goal.goal_type.value)
            else:
                for transition in plan:
                    if not AttackState().satisfies(transition.preconditions):
                        await self._precondition_solver.solve(
                            AttackState(), transition
                        )
                logger.info("attack_graph.plan_failed", goal=goal.goal_type.value)

        return executed_specs

    def _plan_to_chain_spec(
        self, plan: list[AttackTransition], goal: GoalDefinition
    ) -> ChainSpec:
        steps = []
        for i, transition in enumerate(plan):
            steps.append(
                ChainStep(
                    step_index=i,
                    request=self._build_request(transition),
                    role_name="anonymous",
                )
            )
        return ChainSpec(
            chain_type=f"attack_graph:{goal.goal_type.value}",
            steps=steps,
            precondition_finding_ids=[t.finding_id for t in plan],
            description=f"A* plan for {goal.goal_type.value}: {len(plan)} steps",
            executable=True,
        )

    def _build_request(self, transition: AttackTransition) -> Any:
        from hdwp.core.model.schemas import NormalizedRequest
        return NormalizedRequest(
            method="GET",
            url=transition.endpoint or self._target_url,
        )

    async def _execute_plan(
        self, plan: list[AttackTransition], exp_engine: Any
    ) -> tuple[bool, dict]:
        context: dict[str, Any] = {}
        step_results: list[dict] = []

        for i, transition in enumerate(plan):
            request = self._build_request(transition)
            try:
                if exp_engine is not None:
                    result = await exp_engine.execute_single(
                        request, "anonymous", chain_type="attack_graph"
                    )
                else:
                    step_results.append({
                        "step": i,
                        "status_code": 0,
                        "url": transition.endpoint,
                        "finding_id": transition.finding_id,
                    })
                    continue
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "attack_graph.step_failed", step=i, error=str(exc)
                )
                return False, {}

            step_results.append({
                "step": i,
                "status_code": result.response_received.status_code,
                "url": result.request_sent.url,
                "finding_id": transition.finding_id,
            })

        terminal = step_results[-1] if step_results else {}
        status = terminal.get("status_code", 500)
        success = (200 <= status < 300) or (status == 0 and exp_engine is None)

        proof = {
            "chain_type": "attack_graph",
            "steps": step_results,
            "context_values": {k: str(v)[:200] for k, v in context.items()},
            "plan_length": len(plan),
        }
        return success, proof

    async def _save_chain_finding(self, spec: ChainSpec, proof: dict) -> None:
        if not self._repository:
            return
        try:
            await self._repository.save_chain_finding(
                chain_id=generate_id("AGP"),
                session_id=self._session_id,
                chain_type=spec.chain_type,
                trigger_finding_ids=spec.precondition_finding_ids,
                severity="HIGH",
                confidence=0.85,
                proof=proof,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("attack_graph.save_failed", error=str(exc))

    async def run_pending_chains(self, exp_engine: Any) -> list[ChainSpec]:
        return await self.plan_and_execute(exp_engine)

    async def discover_chains(self, finding_ids: list[str] | None = None) -> list[dict]:
        plans = []
        for goal in self._goals:
            plan = self.plan(goal=goal)
            if plan:
                plans.append({
                    "goal_type": goal.goal_type.value,
                    "steps": len(plan),
                    "total_cost": sum(t.cost for t in plan),
                    "finding_ids": [t.finding_id for t in plan],
                    "description": goal.description,
                })
        return plans

    async def run_for_findings(
        self, finding_ids: list[str], exp_engine: Any
    ) -> list[dict]:
        if not self._repository:
            return []
        findings = []
        for fid in finding_ids:
            f = await self._repository.get_finding(fid)
            if f:
                findings.append(f)
                transition = AttackTransition.from_finding(f.model_dump())
                if transition.finding_id not in [t.finding_id for t in self._transitions]:
                    self._transitions.append(transition)

        results = []
        for goal in self._goals:
            plan = self.plan(goal=goal)
            if plan:
                success, proof = await self._execute_plan(plan, exp_engine)
                results.append({
                    "goal_type": goal.goal_type.value,
                    "success": success,
                    **proof,
                })
        return results
