# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, DataFlowMap, FlowEdge, RawObservation


_SENSITIVE_FIELDS = frozenset({
    "password", "token", "secret", "api_key", "apikey",
    "credit_card", "creditcard", "ssn", "email", "phone",
    "dob", "birth", "ip_address", "address",
})


def _to_snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_").replace(" ", "_")


class FlowMapBuilder:
    """Builds DataFlowMap from observation referrer tags, FSM transitions, and DB inference."""

    def __init__(self) -> None:
        self._edge_counts: dict[tuple[str, str, str], int] = {}
        self._last_build_count: int = 0

    def add_observation(self, obs: RawObservation, current_path: str) -> None:
        for tag in obs.tags:
            if tag.startswith("from:"):
                parent = tag[5:]
                if parent and parent != current_path:
                    key = (parent, current_path, "link")
                    self._edge_counts[key] = self._edge_counts.get(key, 0) + 1

    def should_rebuild(self, obs_count: int, fsm_changed: bool) -> bool:
        if fsm_changed:
            return True
        if obs_count - self._last_build_count >= 20:
            self._last_build_count = obs_count
            return True
        return False

    def build(self, model: ApplicationModelData) -> DataFlowMap:
        from hdwp.core.model.schemas import DataFlowMap, FlowEdge

        edges: list[FlowEdge] = []
        seen: set[tuple[str, str]] = set()

        # Edges from referrer chain
        max_count = max(self._edge_counts.values(), default=1)
        for (frm, to, trigger), count in self._edge_counts.items():
            pair = (frm, to)
            if pair not in seen:
                seen.add(pair)
                edges.append(FlowEdge(
                    from_endpoint=frm, to_endpoint=to, trigger=trigger,
                    confidence=round(min(0.95, count / max_count), 3),
                ))

        # Edges from FSM transitions
        if model.fsm:
            state_path: dict[str, str] = {}
            for s in model.fsm.states:
                parts = s.label.split(":", 2)
                if len(parts) >= 2:
                    state_path[s.id] = parts[1]
            for t in model.fsm.transitions:
                frm = state_path.get(t.from_state, "")
                to = state_path.get(t.to_state, "") or t.trigger.url
                if frm and to and frm != to:
                    pair = (frm, to)
                    if pair not in seen:
                        seen.add(pair)
                        edges.append(FlowEdge(
                            from_endpoint=frm, to_endpoint=to,
                            trigger="fsm",
                            confidence=round(model.fsm.confidence, 3),
                        ))

        # Add params transferred
        edges = _add_params_transferred(edges, model)

        # DB inference
        from hdwp.core.model.db_inferrer import DBInferrer
        db_tables = DBInferrer().infer(model)

        # Exfiltration risks
        exfil = _detect_exfiltration(model)

        return DataFlowMap(
            edges=edges,
            db_tables=db_tables,
            exfiltration_risks=exfil,
            last_updated=model.last_updated,
        )


def _add_params_transferred(
    edges: list[FlowEdge], model: ApplicationModelData
) -> list[FlowEdge]:
    """For each edge A→B, find params whose normalized name overlaps with A's response fields."""
    ep_response_fields: dict[str, set[str]] = {}
    for obj in model.objects:
        for ep in model.endpoints:
            ep_param_names = {_to_snake(p.name) for p in model.parameters if p.id in ep.parameters}
            if any(_to_snake(f) in ep_param_names for f in obj.schema_def):
                fields = ep_response_fields.setdefault(ep.path, set())
                for f in obj.schema_def:
                    fields.add(_to_snake(f))

    ep_request_params: dict[str, set[str]] = {}
    for ep in model.endpoints:
        params = {_to_snake(p.name) for p in model.parameters if p.id in ep.parameters}
        if params:
            ep_request_params[ep.path] = params

    for edge in edges:
        a_fields = ep_response_fields.get(edge.from_endpoint, set())
        b_params = ep_request_params.get(edge.to_endpoint, set())
        transferred = sorted(a_fields & b_params)
        if transferred:
            edge.params_transferred = transferred

    return edges


def _detect_exfiltration(model: ApplicationModelData) -> list[str]:
    """Find endpoints that expose sensitive data fields without requiring authentication."""
    risks: list[str] = []
    ep_objects: dict[str, list] = {ep.path: [] for ep in model.endpoints}
    for obj in model.objects:
        for ep in model.endpoints:
            ep_param_names = {_to_snake(p.name) for p in model.parameters if p.id in ep.parameters}
            if any(_to_snake(f) in ep_param_names for f in obj.schema_def):
                ep_objects[ep.path].append(obj)

    for ep in model.endpoints:
        if ep.auth_required:
            continue
        for obj in ep_objects.get(ep.path, []):
            for field in obj.schema_def:
                if _to_snake(field) in _SENSITIVE_FIELDS:
                    if ep.path not in risks:
                        risks.append(ep.path)
                    break

    return risks
