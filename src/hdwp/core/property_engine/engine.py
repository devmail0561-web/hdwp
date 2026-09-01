# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import MODEL_UPDATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty
from hdwp.core.property_engine.inference.authorization import AuthorizationInference
from hdwp.core.property_engine.inference.coherence import CoherenceInference
from hdwp.core.property_engine.inference.concurrency import ConcurrencyInference
from hdwp.core.property_engine.inference.confidentiality import ConfidentialityInference
from hdwp.core.property_engine.inference.integrity import IntegrityInference
from hdwp.core.property_engine.inference.state import StateInference
from hdwp.core.property_engine.inference.temporal import TemporalInference

if TYPE_CHECKING:
    from hdwp.plugins.registry import PluginRegistry

logger = structlog.get_logger()


class SecurityPropertyEngine:
    """
    Central component: infers security properties from the application model.
    Subscribes to model.updated events, publishes property.inferred events.
    """

    def __init__(self, bus: AsyncEventBus, plugin_registry: PluginRegistry | None = None) -> None:
        self._bus = bus
        self._plugin_registry = plugin_registry
        self._properties: dict[str, SecurityProperty] = {}
        self._inference_modules = [
            AuthorizationInference(),
            ConfidentialityInference(),
            StateInference(),
            IntegrityInference(),
            CoherenceInference(),
            TemporalInference(),
            ConcurrencyInference(),
        ]
        bus.on(MODEL_UPDATED, self._on_model_updated)

    async def _on_model_updated(self, event: HDWPEvent) -> None:
        model_data = event.payload
        if isinstance(model_data, dict):
            model_data = ApplicationModelData.model_validate(model_data)

        new_properties: list[SecurityProperty] = []

        # Built-in inference modules
        for module in self._inference_modules:
            inferred = module.infer(model_data)
            for prop in inferred:
                if not self._is_duplicate(prop):
                    self._properties[prop.id] = prop
                    new_properties.append(prop)

        # Plugin-contributed property inference
        if self._plugin_registry is not None:
            for plugin in self._plugin_registry.list_enabled():
                try:
                    plugin_props = plugin.infer_properties(model_data)
                    for prop in plugin_props:
                        if not self._is_duplicate(prop):
                            self._properties[prop.id] = prop
                            new_properties.append(prop)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("plugin.infer_properties_failed", plugin_id=plugin.id, error=str(exc))

        for prop in new_properties:
            logger.info(
                "property.inferred",
                property_id=prop.id,
                type=prop.type.value,
                statement=prop.formal_statement,
            )
            await self._bus.emit(
                PROPERTY_INFERRED, prop.model_dump(), source="property_engine"
            )

    def _is_duplicate(self, prop: SecurityProperty) -> bool:
        return any(
            existing.formal_statement == prop.formal_statement
            for existing in self._properties.values()
        )

    @property
    def properties(self) -> list[SecurityProperty]:
        return [p for p in self._properties.values() if p.status == "active"]
