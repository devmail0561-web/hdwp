# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from hdwp.core.bus.events import MODEL_UPDATED, THREAT_MODEL_UPDATED, HDWPEvent
from hdwp.core.model.schemas import (
    ApplicationModelData,
    BehavioralProfile,
    DataFlowMap,
    EndpointNode,
    FlowEdge,
    ParameterNode,
    RoleNode,
)
from hdwp.core.threat.asset_registry import AssetRegistry, AssetSensitivity
from hdwp.core.threat.scorer import AttackSurfaceScorer
from hdwp.core.threat.engine import ThreatModelEngine


class StubBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Any]] = {}
        self.emitted: list[HDWPEvent] = []

    def on(self, event_type: str, handler: Any) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    async def emit(
        self, event_or_type: Any, payload: Any = None, source: str = ""
    ) -> None:
        if isinstance(event_or_type, HDWPEvent):
            event = event_or_type
        else:
            event = HDWPEvent(type=event_or_type, source=source, payload=payload)
        self.emitted.append(event)
        for handler in self._handlers.get(event.type, []):
            result = handler(event)
            if asyncio.iscoroutine(result):
                await result


def _make_endpoint(path: str, **kw: Any) -> EndpointNode:
    defaults: dict[str, Any] = {"path": path, "methods": ["GET"]}
    defaults.update(kw)
    return EndpointNode(**defaults)


def _make_param(name: str, **kw: Any) -> ParameterNode:
    defaults: dict[str, Any] = {"name": name, "location": "query"}
    defaults.update(kw)
    return ParameterNode(**defaults)


def _make_model(**overrides: Any) -> ApplicationModelData:
    defaults: dict[str, Any] = {"endpoints": [], "parameters": [], "roles": []}
    defaults.update(overrides)
    return ApplicationModelData(**defaults)


def _make_flow_map(edges: list[FlowEdge] | None = None) -> DataFlowMap:
    return DataFlowMap(edges=edges or [])


def test_classify_endpoint_admin_path_returns_internal():
    registry = AssetRegistry()
    ep = _make_endpoint("/admin/users")
    assert registry.classify_endpoint(ep, []) is AssetSensitivity.INTERNAL


def test_classify_endpoint_uuid_path_param_returns_sensitive():
    registry = AssetRegistry()
    ep = _make_endpoint("/api/users/{id}")
    assert registry.classify_endpoint(ep, []) is AssetSensitivity.SENSITIVE


def test_classify_endpoint_price_param_returns_critical():
    registry = AssetRegistry()
    param = _make_param("price")
    ep = _make_endpoint("/api/products", parameters=[param.id])
    assert registry.classify_endpoint(ep, [param]) is AssetSensitivity.CRITICAL


def test_classify_endpoint_balance_param_returns_critical():
    registry = AssetRegistry()
    param = _make_param("balance")
    ep = _make_endpoint("/api/accounts", parameters=[param.id])
    assert registry.classify_endpoint(ep, [param]) is AssetSensitivity.CRITICAL


def test_classify_endpoint_email_param_returns_sensitive():
    registry = AssetRegistry()
    param = _make_param("email")
    ep = _make_endpoint("/api/users", parameters=[param.id])
    assert registry.classify_endpoint(ep, [param]) is AssetSensitivity.SENSITIVE


def test_classify_endpoint_password_param_returns_sensitive():
    registry = AssetRegistry()
    param = _make_param("password", location="body")
    ep = _make_endpoint("/api/login", parameters=[param.id])
    assert registry.classify_endpoint(ep, [param]) is AssetSensitivity.SENSITIVE


def test_classify_endpoint_basic_returns_public():
    registry = AssetRegistry()
    ep = _make_endpoint("/api/health")
    assert registry.classify_endpoint(ep, []) is AssetSensitivity.PUBLIC


def test_score_endpoint_returns_float_in_unit_interval():
    scorer = AttackSurfaceScorer()
    ep = _make_endpoint("/api/data")
    model = _make_model(endpoints=[ep])
    score = scorer.score_endpoint(ep, model)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_score_endpoint_critical_higher_than_public():
    scorer = AttackSurfaceScorer()
    price_param = _make_param("price")
    critical_ep = _make_endpoint("/api/billing", parameters=[price_param.id])
    public_ep = _make_endpoint("/api/health")
    model = _make_model(
        endpoints=[critical_ep, public_ep], parameters=[price_param]
    )
    assert scorer.score_endpoint(critical_ep, model) > scorer.score_endpoint(
        public_ep, model
    )


def test_score_endpoint_more_roles_observed_scores_higher():
    scorer = AttackSurfaceScorer()
    roles = [RoleNode(name="admin"), RoleNode(name="user"), RoleNode(name="guest")]
    ep_one = _make_endpoint("/api/a", roles_observed=["admin"])
    ep_all = _make_endpoint("/api/b", roles_observed=["admin", "user", "guest"])
    model = _make_model(endpoints=[ep_one, ep_all], roles=roles)
    assert scorer.score_endpoint(ep_all, model) > scorer.score_endpoint(ep_one, model)


def test_score_endpoint_high_zscore_anomaly_scores_higher():
    scorer = AttackSurfaceScorer()
    normal_ep = _make_endpoint("/api/normal")
    anomaly_ep = _make_endpoint(
        "/api/anomaly",
        behavioral_profile=BehavioralProfile(
            mean=100.0, std=10.0, sample_count=50, max_zscore_seen=5.0
        ),
    )
    model = _make_model(endpoints=[normal_ep, anomaly_ep])
    assert scorer.score_endpoint(anomaly_ep, model) > scorer.score_endpoint(
        normal_ep, model
    )


@pytest.mark.asyncio
async def test_engine_emits_threat_model_updated_on_model_change():
    bus = StubBus()
    ep = _make_endpoint("/api/data")
    model = _make_model(endpoints=[ep])
    ThreatModelEngine(
        bus=bus, model_accessor=lambda: model, flow_map_accessor=lambda: None
    )
    collected: list[HDWPEvent] = []
    bus.on(THREAT_MODEL_UPDATED, lambda e: collected.append(e))
    await bus.emit(MODEL_UPDATED, payload={}, source="test")
    assert len(collected) == 1
    assert collected[0].type == THREAT_MODEL_UPDATED


@pytest.mark.asyncio
async def test_engine_scores_property_returns_dict_of_floats():
    bus = StubBus()
    ep = _make_endpoint("/api/items")
    model = _make_model(endpoints=[ep])
    engine = ThreatModelEngine(
        bus=bus, model_accessor=lambda: model, flow_map_accessor=lambda: None
    )
    await bus.emit(MODEL_UPDATED, payload={}, source="test")
    scores = engine.scores
    assert isinstance(scores, dict)
    assert "/api/items" in scores
    assert isinstance(scores["/api/items"], float)


@pytest.mark.asyncio
async def test_engine_get_score_unknown_endpoint_returns_zero():
    bus = StubBus()
    engine = ThreatModelEngine(
        bus=bus, model_accessor=lambda: _make_model(), flow_map_accessor=lambda: None
    )
    assert engine.get_score("/nonexistent") == 0.0
