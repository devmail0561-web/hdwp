# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    DataObjectNode,
    EndpointNode,
    ParameterNode,
    PropertyType,
    RoleNode,
)
from hdwp.core.property_engine.inference.coherence import CoherenceInference
from hdwp.core.property_engine.inference.temporal import TemporalInference


def _make_model(**kwargs) -> ApplicationModelData:
    defaults = dict(endpoints=[], parameters=[], objects=[], roles=[], relations=[])
    defaults.update(kwargs)
    return ApplicationModelData(**defaults)


# ── CoherenceInference ────────────────────────────────────────────────────────

def test_coherence_multi_roles_generates_cors_property() -> None:
    ep = EndpointNode(path="/api/data", methods=["GET"], auth_required=True)
    role_a = RoleNode(name="user_a")
    role_b = RoleNode(name="user_b")
    model = _make_model(endpoints=[ep], roles=[role_a, role_b])

    props = CoherenceInference().infer(model)
    cors_props = [p for p in props if "CORS" in p.formal_statement]
    assert len(cors_props) == 1
    assert cors_props[0].type == PropertyType.COHERENCE


def test_coherence_empty_model_returns_empty() -> None:
    assert CoherenceInference().infer(_make_model()) == []


def test_coherence_single_role_no_cors_property() -> None:
    ep = EndpointNode(path="/api/data", methods=["GET"], auth_required=True)
    model = _make_model(endpoints=[ep], roles=[RoleNode(name="user_a")])
    props = CoherenceInference().infer(model)
    cors_props = [p for p in props if "CORS" in p.formal_statement]
    assert len(cors_props) == 0


def test_coherence_sensitive_endpoint_generates_header_property() -> None:
    obj = DataObjectNode(schema={"id": "int"})
    param = ParameterNode(name="path_0", location="path", type_inferred="integer", affects_object=obj.id)
    ep = EndpointNode(path="/api/users/{id}", methods=["GET"], parameters=[param.id])
    model = _make_model(endpoints=[ep], parameters=[param], objects=[obj],
                        roles=[RoleNode(name="user_a"), RoleNode(name="user_b")])

    props = CoherenceInference().infer(model)
    header_props = [p for p in props if "Security headers" in p.formal_statement]
    assert len(header_props) == 1


# ── CoherenceInference — business invariants ─────────────────────────────────

def test_coherence_price_param_generates_business_property() -> None:
    param = ParameterNode(name="price", location="query", type_inferred="integer")
    model = _make_model(parameters=[param])
    props = CoherenceInference().infer(model)
    biz = [p for p in props if "business invariant" in p.formal_statement]
    assert len(biz) == 1
    assert "price" in biz[0].formal_statement


def test_coherence_username_not_business_critical() -> None:
    param = ParameterNode(name="username", location="body", type_inferred="string")
    model = _make_model(parameters=[param])
    props = CoherenceInference().infer(model)
    biz = [p for p in props if "business invariant" in p.formal_statement]
    assert len(biz) == 0


def test_coherence_price_and_amount_both_inferred() -> None:
    p1 = ParameterNode(name="price", location="query", type_inferred="integer")
    p2 = ParameterNode(name="amount", location="body", type_inferred="integer")
    model = _make_model(parameters=[p1, p2])
    props = CoherenceInference().infer(model)
    biz = [p for p in props if "business invariant" in p.formal_statement]
    assert len(biz) == 2


def test_coherence_deduplication_same_name() -> None:
    # Two params with same lowercased name should produce only 1 property
    p1 = ParameterNode(name="price", location="query", type_inferred="integer")
    p2 = ParameterNode(name="price", location="body", type_inferred="integer")
    model = _make_model(parameters=[p1, p2])
    props = CoherenceInference().infer(model)
    biz = [p for p in props if "business invariant" in p.formal_statement]
    assert len(biz) == 1


# ── TemporalInference ─────────────────────────────────────────────────────────

def test_temporal_auth_endpoints_with_roles_generates_property() -> None:
    ep = EndpointNode(path="/api/secret", methods=["GET"], auth_required=True)
    role = RoleNode(name="user_a")
    model = _make_model(endpoints=[ep], roles=[role])

    props = TemporalInference().infer(model)
    assert len(props) == 1
    assert props[0].type == PropertyType.TEMPORAL
    assert "expired(token)" in props[0].formal_statement


def test_temporal_no_auth_endpoints_returns_empty() -> None:
    ep = EndpointNode(path="/api/public", methods=["GET"], auth_required=False)
    model = _make_model(endpoints=[ep], roles=[RoleNode(name="user_a")])
    assert TemporalInference().infer(model) == []


def test_temporal_no_roles_returns_empty() -> None:
    ep = EndpointNode(path="/api/secret", methods=["GET"], auth_required=True)
    model = _make_model(endpoints=[ep], roles=[])
    assert TemporalInference().infer(model) == []


def test_temporal_anonymous_only_returns_empty() -> None:
    ep = EndpointNode(path="/api/secret", methods=["GET"], auth_required=True)
    model = _make_model(endpoints=[ep], roles=[RoleNode(name="anonymous")])
    assert TemporalInference().infer(model) == []
