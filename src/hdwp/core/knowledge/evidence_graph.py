# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RelationType(str, Enum):
    ENABLES = "ENABLES"
    AMPLIFIES = "AMPLIFIES"
    REQUIRES = "REQUIRES"


@dataclass
class EvidenceEdge:
    from_finding_id: str
    to_finding_id: str
    relation_type: RelationType
    session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class EvidenceGraph:
    def __init__(self) -> None:
        self._edges: list[EvidenceEdge] = []
        self._adjacency: dict[str, list[EvidenceEdge]] = {}
        self._reverse: dict[str, list[EvidenceEdge]] = {}

    def add_edge(self, edge: EvidenceEdge) -> bool:
        for existing in self._edges:
            if (
                existing.from_finding_id == edge.from_finding_id
                and existing.to_finding_id == edge.to_finding_id
                and existing.relation_type == edge.relation_type
            ):
                return False

        self._edges.append(edge)
        self._adjacency.setdefault(edge.from_finding_id, []).append(edge)
        self._reverse.setdefault(edge.to_finding_id, []).append(edge)
        return True

    def get_outgoing(self, finding_id: str) -> list[EvidenceEdge]:
        return list(self._adjacency.get(finding_id, []))

    def get_incoming(self, finding_id: str) -> list[EvidenceEdge]:
        return list(self._reverse.get(finding_id, []))

    def get_enabled_by(self, finding_id: str) -> list[str]:
        return [
            e.to_finding_id
            for e in self._adjacency.get(finding_id, [])
            if e.relation_type == RelationType.ENABLES
        ]

    def get_enablers_of(self, finding_id: str) -> list[str]:
        return [
            e.from_finding_id
            for e in self._reverse.get(finding_id, [])
            if e.relation_type == RelationType.ENABLES
        ]

    def has_cycle(self) -> bool:
        visited: set[str] = set()
        in_stack: set[str] = set()
        nodes = set(self._adjacency.keys()) | set(self._reverse.keys())

        def _dfs(node: str) -> bool:
            visited.add(node)
            in_stack.add(node)
            for edge in self._adjacency.get(node, []):
                neighbor = edge.to_finding_id
                if neighbor in in_stack:
                    return True
                if neighbor not in visited and _dfs(neighbor):
                    return True
            in_stack.discard(node)
            return False

        for node in nodes:
            if node not in visited and _dfs(node):
                return True
        return False

    def find_paths(
        self, from_id: str, to_id: str, max_depth: int = 10
    ) -> list[list[str]]:
        paths: list[list[str]] = []
        self._dfs_paths(from_id, to_id, [from_id], set(), paths, max_depth)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: list[str],
        visited: set[str],
        results: list[list[str]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth:
            return
        if current == target and len(path) > 1:
            results.append(list(path))
            return

        visited.add(current)
        for edge in self._adjacency.get(current, []):
            neighbor = edge.to_finding_id
            if neighbor not in visited:
                path.append(neighbor)
                self._dfs_paths(neighbor, target, path, visited, results, max_depth)
                path.pop()
        visited.discard(current)

    @property
    def edges(self) -> list[EvidenceEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        nodes = set(self._adjacency.keys()) | set(self._reverse.keys())
        return len(nodes)
