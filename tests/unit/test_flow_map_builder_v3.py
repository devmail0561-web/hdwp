# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.model.flow_map_builder import (
    FlowMapBuilder,
    _classify_edge,
    _normalize_field,
    _to_snake,
)
from hdwp.core.model.schemas import (
    ApplicationModelData,
    DataFlowMap,
    DataObjectNode,
    EndpointNode,
    FlowEdge,
    FlowEdgeType,
    ParameterNode,
    RoleNode,
)


def _make_param(
    name: str,
    location: str = "query",
    **kw,
) -> ParameterNode:
    return ParameterNode(name=name, location=location, **kw)


def _make_endpoint(
    path: str,
    methods: list[str] | None = None,
    parameters: list[str] | None = None,
    **kw,
) -> EndpointNode:
    return EndpointNode(
        path=path,
        methods=methods or ["GET"],
        parameters=parameters or [],
        **kw,
    )


def _make_model(**overrides) -> ApplicationModelData:
    p_invoice_id = _make_param("invoice_id", location="query")
    p_amount = _make_param("amount", location="body")
    p_email = _make_param("email", location="body")

    ep_invoices = _make_endpoint(
        path="/api/invoices",
        methods=["GET"],
        parameters=[p_invoice_id.id],
    )
    ep_payments = _make_endpoint(
        path="/api/payments",
        methods=["POST"],
        parameters=[p_invoice_id.id, p_amount.id],
    )
    ep_sink = _make_endpoint(
        path="/api/sink",
        methods=["POST"],
        parameters=[p_email.id],
    )

    obj_invoice = DataObjectNode(
        schema_def={"invoice_id": "integer", "amount": "number"},
        sensitivity="public",
    )

    defaults = dict(
        endpoints=[ep_invoices, ep_payments, ep_sink],
        parameters=[p_invoice_id, p_amount, p_email],
        objects=[obj_invoice],
        roles=[],
    )
    defaults.update(overrides)
    return ApplicationModelData(**defaults)


def test_flow_edge_type_enum_values():
    assert FlowEdgeType.PRODUCES.value == "PRODUCES"
    assert FlowEdgeType.CONSUMES.value == "CONSUMES"
    assert FlowEdgeType.TRANSFORMS.value == "TRANSFORMS"
    assert FlowEdgeType.LEAKS.value == "LEAKS"
    assert len(FlowEdgeType) == 4


def test_flow_edge_type_is_str_enum():
    assert isinstance(FlowEdgeType.PRODUCES, str)
    assert FlowEdgeType.CONSUMES == "CONSUMES"


def test_normalize_field_strips_id_suffix():
    assert _normalize_field("user_id") == "user"
    assert _normalize_field("user_ids") == "user"


def test_normalize_field_converts_camel_case():
    assert _normalize_field("invoiceId") == "invoice"
    assert _normalize_field("userId") == "user"


def test_to_snake_basic_conversions():
    assert _to_snake("camelCase") == "camel_case"
    assert _to_snake("HTTPSUrl") == "https_url"
    assert _to_snake("kebab-case") == "kebab_case"
    assert _to_snake("already_snake") == "already_snake"


def test_classify_edge_produces_when_no_overlap():
    ep_resp = {"/a": {"foo", "bar"}}
    ep_req = {"/b": {"baz", "qux"}}
    result = _classify_edge("/a", "/b", ep_resp, ep_req)
    assert result == FlowEdgeType.PRODUCES


def test_classify_edge_consumes_when_overlap_exists():
    ep_resp = {"/api/invoices": {"invoice_id", "total"}}
    ep_req = {"/api/payments": {"invoice_id", "amount"}}
    result = _classify_edge("/api/invoices", "/api/payments", ep_resp, ep_req)
    assert result == FlowEdgeType.CONSUMES


def test_classify_edge_transforms_when_overlap_in_both_io():
    ep_resp = {
        "/a": {"user_id", "name"},
        "/b": {"user_id", "score"},
    }
    ep_req = {"/b": {"user_id"}}
    result = _classify_edge("/a", "/b", ep_resp, ep_req)
    assert result == FlowEdgeType.TRANSFORMS


def test_classify_edge_leaks_sensitive_to_no_output():
    ep_resp = {"/a": {"email", "name"}}
    ep_req = {"/sink": {"email"}}
    result = _classify_edge("/a", "/sink", ep_resp, ep_req)
    assert result == FlowEdgeType.LEAKS


def test_add_implicit_dataflow_edges_discovers_new_edges():
    model = _make_model()

    from hdwp.core.model.flow_map_builder import (
        _add_implicit_dataflow_edges,
        _build_request_param_index,
        _build_response_field_index,
    )

    ep_resp = _build_response_field_index(model)
    ep_req = _build_request_param_index(model)

    edges: list[FlowEdge] = []
    seen: set[tuple[str, str]] = set()

    result = _add_implicit_dataflow_edges(edges, seen, model, ep_resp, ep_req)
    implicit_pairs = {(e.from_endpoint, e.to_endpoint) for e in result}

    assert len(result) >= 1
    assert ("/api/invoices", "/api/payments") in implicit_pairs
    for e in result:
        assert e.trigger == "ajax"
        assert e.confidence <= 0.7


def test_centrality_score_isolated_endpoint():
    builder = FlowMapBuilder()
    flow_map = DataFlowMap(edges=[])
    score = builder.centrality_score("/isolated", flow_map)
    assert score == 0.0


def test_centrality_score_connected_endpoint():
    builder = FlowMapBuilder()
    edges = [
        FlowEdge(from_endpoint="/a", to_endpoint="/b", trigger="link"),
        FlowEdge(from_endpoint="/c", to_endpoint="/b", trigger="ajax"),
        FlowEdge(from_endpoint="/b", to_endpoint="/d", trigger="link"),
    ]
    flow_map = DataFlowMap(edges=edges)

    score_b = builder.centrality_score("/b", flow_map)
    score_a = builder.centrality_score("/a", flow_map)

    assert score_b > score_a
    assert score_b > 0.0
    assert score_b == round((2 + 1) / (4 - 1), 4)


def test_add_params_transferred_uses_normalized_matching():
    from hdwp.core.model.flow_map_builder import _add_params_transferred

    ep_resp = {"/api/items": {"item_id", "item_name"}}
    ep_req = {"/api/orders": {"itemId", "quantity"}}

    edge = FlowEdge(
        from_endpoint="/api/items",
        to_endpoint="/api/orders",
        trigger="link",
    )
    result = _add_params_transferred([edge], ep_resp, ep_req)
    assert result[0].params_transferred == ["itemId"]
