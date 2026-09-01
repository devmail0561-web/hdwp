# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import MODEL_UPDATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.model.schemas import (
    ApplicationModelData,
    DataObjectNode,
    EndpointNode,
    ParameterNode,
    PropertyType,
    RoleNode,
    SecurityProperty,
)
from hdwp.core.property_engine.engine import SecurityPropertyEngine
from hdwp.core.property_engine.inference.authorization import AuthorizationInference
from hdwp.core.property_engine.inference.coherence import CoherenceInference
from hdwp.core.property_engine.inference.concurrency import ConcurrencyInference
from hdwp.core.property_engine.inference.confidentiality import ConfidentialityInference
from hdwp.core.property_engine.inference.integrity import IntegrityInference
from hdwp.core.property_engine.inference.state import StateInference
from hdwp.core.property_engine.inference.temporal import TemporalInference


def _make_model(**kwargs) -> ApplicationModelData:  # type: ignore[no-untyped-def]
    defaults = dict(
        endpoints=[],
        parameters=[],
        objects=[],
        roles=[],
        relations=[],
        last_updated="2026-09-01T00:00:00Z",
    )
    defaults.update(kwargs)
    return ApplicationModelData(**defaults)


# ── AuthorizationInference unit tests ────────────────────────


def test_authorization_bola_property() -> None:
    param = ParameterNode(
        id="PARAM-001",
        name="user_id",
        location="path",
        type_inferred="integer",
        affects_object="OBJ-001",
    )
    ep = EndpointNode(
        id="EP-001",
        path="/api/users/{id_0}",
        methods=["GET"],
        parameters=["PARAM-001"],
    )
    roles = [
        RoleNode(id="ROLE-001", name="user_a"),
        RoleNode(id="ROLE-002", name="user_b"),
    ]
    model = _make_model(endpoints=[ep], parameters=[param], roles=roles)

    props = AuthorizationInference().infer(model)
    bola_props = [
        p for p in props if "owner(resource) = S" in p.formal_statement
    ]
    assert len(bola_props) >= 1
    assert bola_props[0].type == PropertyType.AUTHORIZATION
    assert bola_props[0].inference_confidence == 0.8


def test_authorization_bola_lower_confidence_single_role() -> None:
    param = ParameterNode(
        id="PARAM-001",
        name="item_id",
        location="path",
        type_inferred="uuid",
        affects_object="OBJ-001",
    )
    model = _make_model(
        parameters=[param],
        roles=[RoleNode(id="ROLE-001", name="user_a")],
    )

    props = AuthorizationInference().infer(model)
    bola_props = [
        p for p in props if "owner(resource) = S" in p.formal_statement
    ]
    assert len(bola_props) == 1
    assert bola_props[0].inference_confidence == 0.5


def test_authorization_endpoint_property() -> None:
    ep = EndpointNode(
        id="EP-001",
        path="/api/admin/users",
        methods=["GET"],
        auth_required=True,
        roles_observed=["admin"],
    )
    model = _make_model(endpoints=[ep])

    props = AuthorizationInference().infer(model)
    ep_props = [p for p in props if "S.role in" in p.formal_statement]
    assert len(ep_props) == 1
    assert ep_props[0].inference_confidence == 0.7
    assert "admin" in ep_props[0].formal_statement


def test_authorization_role_separation() -> None:
    role_a = RoleNode(
        id="ROLE-001",
        name="user",
        observed_permissions=["GET:/api/profile", "GET:/api/items"],
    )
    role_b = RoleNode(
        id="ROLE-002",
        name="admin",
        observed_permissions=["GET:/api/profile", "GET:/api/admin/dashboard"],
    )
    model = _make_model(roles=[role_a, role_b])

    props = AuthorizationInference().infer(model)
    sep_props = [p for p in props if "cannot access" in p.formal_statement]
    assert len(sep_props) == 2
    statements = [p.formal_statement for p in sep_props]
    assert any("admin" in s and "user" in s for s in statements)


def test_no_bola_without_affects_object() -> None:
    param = ParameterNode(
        id="PARAM-001",
        name="page",
        location="query",
        type_inferred="integer",
        affects_object=None,
    )
    model = _make_model(parameters=[param])
    props = AuthorizationInference().infer(model)
    bola_props = [
        p for p in props if "owner(resource) = S" in p.formal_statement
    ]
    assert len(bola_props) == 0


# ── ConfidentialityInference unit tests ──────────────────────


def test_confidentiality_private_object() -> None:
    obj = DataObjectNode(
        id="OBJ-001",
        schema={"id": "int", "email": "str"},
        owner_parameter="PARAM-001",
        sensitivity="private",
    )
    model = _make_model(objects=[obj])

    props = ConfidentialityInference().infer(model)
    assert len(props) == 1
    assert props[0].type == PropertyType.CONFIDENTIALITY
    assert "owner(object) = A" in props[0].formal_statement


def test_confidentiality_public_object_ignored() -> None:
    obj = DataObjectNode(
        id="OBJ-001",
        schema={"id": "int"},
        owner_parameter="PARAM-001",
        sensitivity="public",
    )
    model = _make_model(objects=[obj])
    props = ConfidentialityInference().infer(model)
    assert len(props) == 0


def test_confidentiality_no_owner_ignored() -> None:
    obj = DataObjectNode(
        id="OBJ-001",
        schema={"id": "int"},
        owner_parameter=None,
        sensitivity="sensitive",
    )
    model = _make_model(objects=[obj])
    props = ConfidentialityInference().infer(model)
    assert len(props) == 0


# ── Stub modules ─────────────────────────────────────────────


def test_stub_modules_return_empty() -> None:
    model = _make_model()
    assert StateInference().infer(model) == []
    assert IntegrityInference().infer(model) == []
    assert CoherenceInference().infer(model) == []
    assert TemporalInference().infer(model) == []
    assert ConcurrencyInference().infer(model) == []


# ── SecurityPropertyEngine integration tests ─────────────────


@pytest.mark.asyncio
async def test_engine_subscribes_to_model_updated() -> None:
    bus = AsyncEventBus()
    _engine = SecurityPropertyEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(PROPERTY_INFERRED, lambda e: received.append(e))

    param = ParameterNode(
        id="PARAM-001",
        name="user_id",
        location="path",
        type_inferred="integer",
        affects_object="OBJ-001",
    )
    ep = EndpointNode(
        id="EP-001",
        path="/api/users/{id_0}",
        methods=["GET"],
        auth_required=True,
        roles_observed=["user_a"],
        parameters=["PARAM-001"],
    )
    roles = [
        RoleNode(id="ROLE-001", name="user_a"),
        RoleNode(id="ROLE-002", name="user_b"),
    ]
    model = _make_model(endpoints=[ep], parameters=[param], roles=roles)

    await bus.emit(MODEL_UPDATED, model.model_dump(), source="test")
    await bus.drain()

    assert len(received) >= 1
    payloads = [SecurityProperty.model_validate(e.payload) for e in received]
    assert any(p.type == PropertyType.AUTHORIZATION for p in payloads)


@pytest.mark.asyncio
async def test_engine_deduplicates_properties() -> None:
    bus = AsyncEventBus()
    engine = SecurityPropertyEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(PROPERTY_INFERRED, lambda e: received.append(e))

    ep = EndpointNode(
        id="EP-001",
        path="/api/admin",
        methods=["GET"],
        auth_required=True,
        roles_observed=["admin"],
    )
    model = _make_model(endpoints=[ep])

    await bus.emit(MODEL_UPDATED, model.model_dump(), source="test")
    await bus.drain()
    first_count = len(received)
    assert first_count >= 1

    await bus.emit(MODEL_UPDATED, model.model_dump(), source="test")
    await bus.drain()
    assert len(received) == first_count


@pytest.mark.asyncio
async def test_no_properties_from_empty_model() -> None:
    bus = AsyncEventBus()
    engine = SecurityPropertyEngine(bus)

    received: list[HDWPEvent] = []
    bus.on(PROPERTY_INFERRED, lambda e: received.append(e))

    model = _make_model()
    await bus.emit(MODEL_UPDATED, model.model_dump(), source="test")
    await bus.drain()

    assert len(received) == 0
    assert len(engine.properties) == 0
