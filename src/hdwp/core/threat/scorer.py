# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING

from hdwp.core.threat.asset_registry import AssetRegistry, AssetSensitivity

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, DataFlowMap, EndpointNode


_SENSITIVITY_WEIGHT: dict[AssetSensitivity, float] = {
    AssetSensitivity.PUBLIC: 0.2,
    AssetSensitivity.INTERNAL: 0.5,
    AssetSensitivity.SENSITIVE: 0.7,
    AssetSensitivity.CRITICAL: 1.0,
}


class AttackSurfaceScorer:
    def __init__(self, asset_registry: AssetRegistry | None = None) -> None:
        self._registry = asset_registry or AssetRegistry()

    def score_endpoint(
        self,
        ep: EndpointNode,
        model: ApplicationModelData,
        flow_map: DataFlowMap | None = None,
    ) -> float:
        sensitivity = self._registry.classify_endpoint(ep, model.parameters)
        asset_w = _SENSITIVITY_WEIGHT[sensitivity]

        role_boundary = self._role_boundary_factor(ep, model)
        centrality = self._dataflow_centrality(ep, flow_map) if flow_map else 0.1
        anomaly = self._behavioral_anomaly_factor(ep)

        raw = asset_w * role_boundary * (1.0 + centrality) * (1.0 + anomaly)
        return round(min(1.0, raw), 4)

    def score_all(
        self,
        model: ApplicationModelData,
        flow_map: DataFlowMap | None = None,
    ) -> dict[str, float]:
        return {
            ep.path: self.score_endpoint(ep, model, flow_map)
            for ep in model.endpoints
        }

    def _role_boundary_factor(self, ep: EndpointNode, model: ApplicationModelData) -> float:
        n_roles = len(model.roles) or 1
        observed = len(ep.roles_observed)
        if observed == 0:
            return 0.3
        if observed >= n_roles:
            return 1.0
        return round(0.3 + 0.7 * (observed / n_roles), 3)

    def _dataflow_centrality(self, ep: EndpointNode, flow_map: DataFlowMap) -> float:
        in_degree = sum(1 for e in flow_map.edges if e.to_endpoint == ep.path)
        out_degree = sum(1 for e in flow_map.edges if e.from_endpoint == ep.path)
        total = len({e.from_endpoint for e in flow_map.edges} | {e.to_endpoint for e in flow_map.edges})
        if total <= 1:
            return 0.0
        return round((in_degree + out_degree) / (total - 1), 4)

    def _behavioral_anomaly_factor(self, ep: EndpointNode) -> float:
        if not ep.behavioral_profile or not ep.behavioral_profile.max_zscore_seen:
            return 0.0
        z = abs(ep.behavioral_profile.max_zscore_seen)
        if z < 2.0:
            return 0.0
        return round(min(1.0, (z - 2.0) / 3.0), 3)
