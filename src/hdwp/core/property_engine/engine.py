# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import MODEL_UPDATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty

if TYPE_CHECKING:
    from hdwp.core.property_engine.inference_registry import InferenceRegistry
    from hdwp.plugins.registry import PluginRegistry

logger = structlog.get_logger()


class SecurityPropertyEngine:
    """
    Central component: infers security properties from the application model.
    Subscribes to model.updated events, publishes property.inferred events.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        plugin_registry: PluginRegistry | None = None,
        inference_registry: InferenceRegistry | None = None,
    ) -> None:
        self._bus = bus
        self._plugin_registry = plugin_registry
        self._properties: dict[str, SecurityProperty] = {}

        if inference_registry is None:
            from hdwp.core.property_engine.inference_registry import InferenceRegistry as _IR
            inference_registry = _IR.default()
        self._inference_registry = inference_registry

        bus.on(MODEL_UPDATED, self._on_model_updated)

    def _signature(self, prop: SecurityProperty) -> tuple[str, str, str]:
        """Déduplication sémantique : (type, nœuds triés, statement) — evite la collision entre
        proprietes du meme type sur les memes noeuds mais avec des semantiques differentes."""
        return (prop.type.value, ";".join(sorted(prop.model_nodes)), prop.formal_statement)

    def _is_duplicate(self, prop: SecurityProperty) -> bool:
        sig = self._signature(prop)
        return any(self._signature(p) == sig for p in self._properties.values())

    async def _on_model_updated(self, event: HDWPEvent) -> None:
        model_data = event.payload
        if isinstance(model_data, dict):
            model_data = ApplicationModelData.model_validate(model_data)

        new_properties: list[SecurityProperty] = []

        # Invalider les propriétés stales dont les model_nodes ne sont plus dans le modèle
        current_node_ids = (
            {ep.id for ep in model_data.endpoints}
            | {p.id for p in model_data.parameters}
            | {o.id for o in model_data.objects}
        )
        for prop in list(self._properties.values()):
            if (prop.status == "active"
                    and prop.model_nodes
                    and not any(nid in current_node_ids for nid in prop.model_nodes)):
                prop.status = "invalidated"
                logger.debug("property.invalidated", prop_id=prop.id, type=prop.type.value)

        # Built-in + external inference modules from registry
        for module in self._inference_registry.list_active():
            try:
                inferred = module.infer(model_data)  # type: ignore[union-attr]
                for prop in inferred:
                    if not self._is_duplicate(prop):
                        self._properties[prop.id] = prop
                        new_properties.append(prop)
            except Exception as exc:  # noqa: BLE001
                name = getattr(module, "provider_id", lambda: type(module).__name__)()
                logger.warning("inference.module_failed", module=name, error=str(exc))

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

    @property
    def properties(self) -> list[SecurityProperty]:
        return [p for p in self._properties.values() if p.status == "active"]
