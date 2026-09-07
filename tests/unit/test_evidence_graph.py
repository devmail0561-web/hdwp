# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.knowledge.evidence_graph import (
    EvidenceEdge,
    EvidenceGraph,
    RelationType,
)


def _make_edge(
    from_id: str = "F-001",
    to_id: str = "F-002",
    relation: RelationType = RelationType.ENABLES,
    session_id: str = "S-001",
) -> EvidenceEdge:
    return EvidenceEdge(
        from_finding_id=from_id,
        to_finding_id=to_id,
        relation_type=relation,
        session_id=session_id,
    )


def test_add_edge_stores_and_returns_via_property():
    graph = EvidenceGraph()
    edge = _make_edge()
    result = graph.add_edge(edge)
    assert result is True
    assert len(graph.edges) == 1
    assert graph.edges[0] is edge


def test_add_edge_deduplicates():
    graph = EvidenceGraph()
    edge1 = _make_edge()
    edge2 = _make_edge()
    assert graph.add_edge(edge1) is True
    assert graph.add_edge(edge2) is False
    assert len(graph.edges) == 1


def test_get_outgoing():
    graph = EvidenceGraph()
    e1 = _make_edge("A", "B")
    e2 = _make_edge("A", "C")
    e3 = _make_edge("B", "C")
    graph.add_edge(e1)
    graph.add_edge(e2)
    graph.add_edge(e3)

    outgoing = graph.get_outgoing("A")
    assert len(outgoing) == 2
    assert {e.to_finding_id for e in outgoing} == {"B", "C"}


def test_get_incoming():
    graph = EvidenceGraph()
    e1 = _make_edge("A", "C")
    e2 = _make_edge("B", "C")
    graph.add_edge(e1)
    graph.add_edge(e2)

    incoming = graph.get_incoming("C")
    assert len(incoming) == 2
    assert {e.from_finding_id for e in incoming} == {"A", "B"}


def test_get_enabled_by_filters_enables_only():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B", RelationType.ENABLES))
    graph.add_edge(_make_edge("A", "C", RelationType.AMPLIFIES))
    graph.add_edge(_make_edge("A", "D", RelationType.ENABLES))

    enabled = graph.get_enabled_by("A")
    assert set(enabled) == {"B", "D"}


def test_get_enablers_of_filters_enables_only():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "Z", RelationType.ENABLES))
    graph.add_edge(_make_edge("B", "Z", RelationType.REQUIRES))
    graph.add_edge(_make_edge("C", "Z", RelationType.ENABLES))

    enablers = graph.get_enablers_of("Z")
    assert set(enablers) == {"A", "C"}


def test_has_cycle_returns_false_for_acyclic():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B"))
    graph.add_edge(_make_edge("B", "C"))
    graph.add_edge(_make_edge("A", "C"))
    assert graph.has_cycle() is False


def test_has_cycle_returns_true_for_cycle():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B"))
    graph.add_edge(_make_edge("B", "C"))
    graph.add_edge(_make_edge("C", "A"))
    assert graph.has_cycle() is True


def test_find_paths_between_connected_nodes():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B"))
    graph.add_edge(_make_edge("B", "C"))

    paths = graph.find_paths("A", "C")
    assert len(paths) == 1
    assert paths[0] == ["A", "B", "C"]


def test_find_paths_returns_empty_for_disconnected():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B"))
    graph.add_edge(_make_edge("C", "D"))

    paths = graph.find_paths("A", "D")
    assert paths == []


def test_node_count():
    graph = EvidenceGraph()
    graph.add_edge(_make_edge("A", "B"))
    graph.add_edge(_make_edge("B", "C"))
    assert graph.node_count == 3


def test_multiple_relation_types_coexist():
    graph = EvidenceGraph()
    e1 = _make_edge("A", "B", RelationType.ENABLES)
    e2 = _make_edge("A", "B", RelationType.AMPLIFIES)
    e3 = _make_edge("A", "B", RelationType.REQUIRES)

    assert graph.add_edge(e1) is True
    assert graph.add_edge(e2) is True
    assert graph.add_edge(e3) is True
    assert len(graph.edges) == 3

    outgoing = graph.get_outgoing("A")
    assert len(outgoing) == 3
    assert {e.relation_type for e in outgoing} == {
        RelationType.ENABLES,
        RelationType.AMPLIFIES,
        RelationType.REQUIRES,
    }
