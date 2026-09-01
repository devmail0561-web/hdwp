# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import ApplicationModelData, EndpointNode, PropertyType
from hdwp.core.property_engine.inference.state import StateInference


def _make_model(paths: list[str]) -> ApplicationModelData:
    endpoints = [EndpointNode(path=p, methods=["GET"]) for p in paths]
    return ApplicationModelData(endpoints=endpoints)


def test_step_endpoints_infer_state_property():
    """Endpoints with step/stage pattern produce a STATE property."""
    model = _make_model(["/checkout/step1", "/checkout/step2", "/checkout/step3"])
    inf = StateInference()
    props = inf.infer(model)
    assert len(props) == 1
    assert props[0].type == PropertyType.STATE
    assert "step" in props[0].formal_statement.lower() or "State sequence" in props[0].formal_statement


def test_numbered_path_endpoints_infer_state_property():
    """Endpoints ending with /1, /2 produce a STATE property."""
    model = _make_model(["/wizard/1", "/wizard/2"])
    inf = StateInference()
    props = inf.infer(model)
    assert len(props) == 1
    assert props[0].type == PropertyType.STATE


def test_no_step_endpoints_returns_empty():
    """Regular endpoints without step patterns return empty list."""
    model = _make_model(["/api/users", "/api/posts", "/api/login"])
    inf = StateInference()
    props = inf.infer(model)
    assert props == []


def test_single_step_endpoint_not_enough():
    """A single step endpoint is not enough to infer a state property."""
    model = _make_model(["/checkout/step1"])
    inf = StateInference()
    props = inf.infer(model)
    assert props == []


def test_empty_model_returns_empty():
    """Empty model produces no properties."""
    model = _make_model([])
    inf = StateInference()
    assert inf.infer(model) == []
