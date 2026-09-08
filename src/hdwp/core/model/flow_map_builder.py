# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import (
        ApplicationModelData,
        DataFlowMap,
        FlowEdge,
        RawObservation,
    )


_SENSITIVE_FIELDS = frozenset({
    "password", "token", "secret", "api_key", "apikey",
    "credit_card", "creditcard", "ssn", "email", "phone",
    "dob", "birth", "ip_address", "address",
})


def _to_snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_").replace(" ", "_")


def _normalize_field(name: str) -> str:
    s = _to_snake(name)
    return s.removesuffix("_ids").removesuffix("_id")


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

        ep_response_fields = _build_response_field_index(model)
        ep_request_params = _build_request_param_index(model)

        # Edges from referrer chain
        max_count = max(self._edge_counts.values(), default=1)
        for (frm, to, trigger), count in self._edge_counts.items():
            pair = (frm, to)
            if pair not in seen:
                seen.add(pair)
                edge_type = _classify_edge(frm, to, ep_response_fields, ep_request_params)
                edges.append(FlowEdge(
                    from_endpoint=frm, to_endpoint=to, trigger=trigger,
                    edge_type=edge_type,
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
                        edge_type = _classify_edge(frm, to, ep_response_fields, ep_request_params)
                        edges.append(FlowEdge(
                            from_endpoint=frm, to_endpoint=to,
                            trigger="fsm",
                            edge_type=edge_type,
                            confidence=round(model.fsm.confidence, 3),
                        ))

        # Add params transferred
        edges = _add_params_transferred(edges, ep_response_fields, ep_request_params)

        # Discover implicit data-flow edges not captured by referrer/FSM
        edges = _add_implicit_dataflow_edges(
            edges, seen, model, ep_response_fields, ep_request_params,
        )

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

    def centrality_score(self, endpoint_id: str, flow_map: DataFlowMap) -> float:
        in_degree = 0
        out_degree = 0
        for edge in flow_map.edges:
            if edge.to_endpoint == endpoint_id:
                in_degree += 1
            if edge.from_endpoint == endpoint_id:
                out_degree += 1
        total_endpoints = len({e.from_endpoint for e in flow_map.edges} | {e.to_endpoint for e in flow_map.edges})
        if total_endpoints <= 1:
            return 0.0
        return round((in_degree + out_degree) / (total_endpoints - 1), 4)


def _build_response_field_index(
    model: ApplicationModelData,
) -> dict[str, set[str]]:
    ep_response_fields: dict[str, set[str]] = {}
    for obj in model.objects:
        for ep in model.endpoints:
            ep_param_names = {_to_snake(p.name) for p in model.parameters if p.id in ep.parameters}
            if any(_to_snake(f) in ep_param_names for f in obj.schema_def):
                fields = ep_response_fields.setdefault(ep.path, set())
                for f in obj.schema_def:
                    fields.add(_to_snake(f))
    return ep_response_fields


def _build_request_param_index(
    model: ApplicationModelData,
) -> dict[str, set[str]]:
    ep_request_params: dict[str, set[str]] = {}
    for ep in model.endpoints:
        params = {_to_snake(p.name) for p in model.parameters if p.id in ep.parameters}
        if params:
            ep_request_params[ep.path] = params
    return ep_request_params


def _classify_edge(
    from_ep: str,
    to_ep: str,
    ep_response_fields: dict[str, set[str]],
    ep_request_params: dict[str, set[str]],
) -> FlowEdgeType:
    from hdwp.core.model.schemas import FlowEdgeType

    a_fields = ep_response_fields.get(from_ep, set())
    b_params = ep_request_params.get(to_ep, set())

    a_normalized = {_normalize_field(f) for f in a_fields}
    b_normalized = {_normalize_field(p) for p in b_params}

    overlap = a_normalized & b_normalized

    if not overlap:
        return FlowEdgeType.PRODUCES

    has_sensitive = any(f in _SENSITIVE_FIELDS for f in overlap)
    b_fields = ep_response_fields.get(to_ep, set())
    b_out_normalized = {_normalize_field(f) for f in b_fields}

    if has_sensitive and not b_out_normalized:
        return FlowEdgeType.LEAKS

    if overlap & b_out_normalized:
        return FlowEdgeType.TRANSFORMS

    return FlowEdgeType.CONSUMES


def _add_params_transferred(
    edges: list[FlowEdge],
    ep_response_fields: dict[str, set[str]],
    ep_request_params: dict[str, set[str]],
) -> list[FlowEdge]:
    for edge in edges:
        a_fields = ep_response_fields.get(edge.from_endpoint, set())
        b_params = ep_request_params.get(edge.to_endpoint, set())

        a_normalized = {_normalize_field(f): f for f in a_fields}
        b_normalized = {_normalize_field(p): p for p in b_params}

        overlap_keys = set(a_normalized.keys()) & set(b_normalized.keys())
        transferred = sorted(b_normalized[k] for k in overlap_keys)
        if transferred:
            edge.params_transferred = transferred

    return edges


def _add_implicit_dataflow_edges(
    edges: list[FlowEdge],
    seen: set[tuple[str, str]],
    model: ApplicationModelData,
    ep_response_fields: dict[str, set[str]],
    ep_request_params: dict[str, set[str]],
) -> list[FlowEdge]:
    from hdwp.core.model.schemas import FlowEdge

    for ep_a in model.endpoints:
        a_fields = ep_response_fields.get(ep_a.path, set())
        if not a_fields:
            continue
        a_normalized = {_normalize_field(f) for f in a_fields}

        for ep_b in model.endpoints:
            if ep_a.path == ep_b.path:
                continue
            pair = (ep_a.path, ep_b.path)
            if pair in seen:
                continue

            b_params = ep_request_params.get(ep_b.path, set())
            if not b_params:
                continue
            b_normalized = {_normalize_field(p) for p in b_params}

            overlap = a_normalized & b_normalized
            if len(overlap) < 1:
                continue

            seen.add(pair)
            edge_type = _classify_edge(ep_a.path, ep_b.path, ep_response_fields, ep_request_params)
            transferred = sorted(overlap)
            edges.append(FlowEdge(
                from_endpoint=ep_a.path,
                to_endpoint=ep_b.path,
                trigger="ajax",
                edge_type=edge_type,
                params_transferred=transferred,
                confidence=round(min(0.7, len(overlap) * 0.15), 3),
            ))

    return edges


def _detect_exfiltration(model: ApplicationModelData) -> list[str]:
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
