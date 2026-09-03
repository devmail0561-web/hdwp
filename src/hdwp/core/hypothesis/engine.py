# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import HYPOTHESIS_GENERATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
)

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.plugins.registry import PluginRegistry
    from hdwp.store.repository import Repository

logger = structlog.get_logger()


class HypothesisEngine:
    """
    Subscribes to property.inferred events.
    For each SecurityProperty, generates falsifiable hypotheses.
    Publishes hypothesis.generated events.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable[[], ApplicationModelData | None] | None = None,
        plugin_registry: PluginRegistry | None = None,
        repository: Repository | None = None,
        prioritizer: HypothesisPrioritizer | None = None,
        llm_layer: LLMLayerProtocol | None = None,
    ) -> None:
        self._bus = bus
        self._hypotheses: dict[str, Hypothesis] = {}
        self._prioritizer = prioritizer or HypothesisPrioritizer()
        self._model_accessor = model_accessor
        self._plugin_registry = plugin_registry
        self._repository = repository
        self._llm_layer = llm_layer
        bus.on(PROPERTY_INFERRED, self._on_property_inferred)

    async def _on_property_inferred(self, event: HDWPEvent) -> None:
        prop_data = event.payload
        if isinstance(prop_data, dict):
            prop = SecurityProperty.model_validate(prop_data)
        else:
            prop = prop_data

        hypotheses = self._generate_hypotheses(prop)

        # Also ask plugins if a model snapshot is available
        if self._plugin_registry is not None and self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                for plugin in self._plugin_registry.list_enabled():
                    try:
                        plugin_hyps = plugin.generate_hypotheses(model)
                        hypotheses.extend(plugin_hyps)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("plugin.generate_hypotheses_failed", plugin_id=plugin.id, error=str(exc))

        # LLM complementary hypotheses (ADR-002 : informationnelles, required_experiments=[])
        if self._llm_layer is not None and self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                try:
                    statements = await self._llm_layer.propose_hypotheses(model, len(self._hypotheses))
                    for stmt in statements:
                        hyp = Hypothesis(
                            source_plugin="llm",
                            property_id=prop.id,
                            statement=stmt,
                            priority="LOW",
                            priority_rationale="LLM complementary hypothesis — ADR-002",
                            required_experiments=[],
                        )
                        if not self._is_duplicate(hyp):
                            hypotheses.append(hyp)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("llm.propose_hypotheses_error", error=str(exc))

        for hyp in hypotheses:
            if not self._is_duplicate(hyp):
                self._hypotheses[hyp.id] = hyp
                if self._repository is not None:
                    try:
                        await self._repository.save_hypothesis(hyp)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("hypothesis.save_failed", hypothesis_id=hyp.id, error=str(exc))
                await self._bus.emit(
                    HYPOTHESIS_GENERATED, hyp.model_dump(), source="hypothesis_engine"
                )

    def _generate_hypotheses(self, prop: SecurityProperty) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        if prop.type == PropertyType.AUTHORIZATION:
            stmt_lower = prop.formal_statement.lower()
            if ("parameter" in stmt_lower or "access(s, resource)" in stmt_lower
                    or "bola" in stmt_lower or "ownership" in stmt_lower
                    or "object level" in stmt_lower):
                priority, rationale = self._prioritizer.compute_priority(
                    property_type=prop.type,
                    affected_node_count=len(prop.model_nodes),
                    total_endpoints=max(len(prop.model_nodes), 1),
                    observation_count=len(prop.source_observations),
                )
                hypotheses.append(
                    Hypothesis(
                        source_plugin="core.hypothesis_engine",
                        property_id=prop.id,
                        statement=(
                            f"The property '{prop.formal_statement}' can be violated "
                            "by swapping identity credentials while accessing the same resource."
                        ),
                        priority=priority,
                        priority_rationale=rationale,
                        required_experiments=[
                            ExperimentSpec(
                                mutation_type="identity_swap",
                                base_request=NormalizedRequest(method="GET", url=""),
                                mutation_params={
                                    "property_id": prop.id,
                                    "model_nodes": prop.model_nodes,
                                },
                                description="Swap auth credentials and attempt same resource access",
                            ),
                            ExperimentSpec(
                                mutation_type="object_ref_change",
                                base_request=NormalizedRequest(method="GET", url=""),
                                mutation_params={
                                    "property_id": prop.id,
                                    "model_nodes": prop.model_nodes,
                                },
                                description="Change object reference ID while keeping same auth",
                            ),
                        ],
                    )
                )

            if "role" in stmt_lower and "cannot access" in stmt_lower:
                priority, rationale = self._prioritizer.compute_priority(
                    property_type=prop.type,
                    affected_node_count=len(prop.model_nodes),
                    total_endpoints=max(len(prop.model_nodes), 1),
                    observation_count=len(prop.source_observations),
                )
                # Derive endpoint_path and target_role from model snapshot
                if self._model_accessor is None:
                    return hypotheses
                model = self._model_accessor()
                endpoint_path = ""
                for ep in model.endpoints:
                    if any(n in prop.model_nodes for n in ([ep.id] + ep.parameters)):
                        endpoint_path = ep.path
                        break
                # Pick least-privileged role as attacker
                role_names = [r.name for r in model.roles]
                target_role = "anonymous" if "anonymous" in role_names else (role_names[0] if role_names else "anonymous")
                if endpoint_path:
                    hypotheses.append(
                        Hypothesis(
                            source_plugin="core.hypothesis_engine",
                            property_id=prop.id,
                            statement=(
                                f"The property '{prop.formal_statement}' can be violated "
                                "by using a lower-privilege role's credentials on a restricted endpoint."
                            ),
                            priority=priority,
                            priority_rationale=rationale,
                            required_experiments=[
                                ExperimentSpec(
                                    mutation_type="privilege_escalation",
                                    base_request=NormalizedRequest(method="GET", url=""),
                                    mutation_params={
                                        "property_id": prop.id,
                                        "endpoint_path": endpoint_path,
                                        "target_role": target_role,
                                        "model_nodes": prop.model_nodes,
                                    },
                                    description=f"Access '{endpoint_path}' with role '{target_role}'",
                                ),
                            ],
                        )
                    )

        elif prop.type == PropertyType.INTEGRITY:
            param_name = self._extract_param_name(prop.formal_statement)
            param_location = self._extract_param_location(prop.formal_statement)
            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )

            if param_name and "does not accept unexpected fields" not in prop.formal_statement:
                # Injection classique : SQLi, XSS, SSTI
                experiments = [
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "' OR '1'='1",
                            "payload_type": "sqli",
                        },
                        description=f"SQLi probe on '{param_name}'",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "<script>alert(1)</script>",
                            "payload_type": "xss",
                        },
                        description=f"XSS probe on '{param_name}'",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="GET", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "{{7*7}}",
                            "payload_type": "ssti",
                            "expected_result": "49",
                        },
                        description=f"SSTI probe on '{param_name}'",
                    ),
                ]
                hypotheses.append(Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=f"Le paramètre '{param_name}' est vulnérable à une injection.",
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=experiments,
                ))

            elif "does not accept unexpected fields" in prop.formal_statement:
                # Mass assignment
                hypotheses.append(Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement="L'endpoint accepte des champs supplémentaires non prévus (mass assignment).",
                    priority="MEDIUM",
                    priority_rationale="Mass assignment potentiel sur endpoint POST/PUT",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="POST", url=""),
                        mutation_params={
                            "parameter_name": "is_admin",
                            "parameter_location": "body",
                            "payload": "true",
                            "payload_type": "mass_assign",
                            "extra_field": "is_admin",
                        },
                        description="Mass assignment probe: inject is_admin=true in body",
                    )],
                ))

        elif prop.type == PropertyType.COHERENCE:
            # Business invariant uniquement (CORS/headers n'ont pas de mutation active)
            if "business invariant" not in prop.formal_statement:
                return hypotheses

            model = self._model_accessor() if self._model_accessor else None
            if model is None:
                return hypotheses

            param_nodes = set(prop.model_nodes)
            target_param = next(
                (p for p in model.parameters if p.id in param_nodes),
                None,
            )
            if target_param is None:
                return hypotheses

            business_probes = [
                ("0",       "boundary", "business boundary: zero value"),
                ("-1",      "boundary", "business boundary: negative"),
                ("-9999",   "boundary", "business boundary: large negative"),
                ("0.001",   "boundary", "business boundary: fractional"),
                ("9999999", "boundary", "business boundary: overflow"),
            ]

            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )

            hypotheses.append(
                Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=(
                        f"Business logic flaw: parameter '{target_param.name}' accepts "
                        f"invalid values (zero/negative/overflow) without proper validation"
                    ),
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "parameter_name": target_param.name,
                                "parameter_location": target_param.location,
                                "payload": probe_val,
                                "payload_type": probe_type,
                                "expected_result": "",
                            },
                            description=probe_desc,
                        )
                        for probe_val, probe_type, probe_desc in business_probes
                    ],
                )
            )

        elif prop.type == PropertyType.CONFIDENTIALITY:
            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )
            hypotheses.append(
                Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=(
                        f"The property '{prop.formal_statement}' can be violated "
                        "by querying another user's data."
                    ),
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="identity_swap",
                            base_request=NormalizedRequest(method="GET", url=""),
                            mutation_params={
                                "property_id": prop.id,
                                "model_nodes": prop.model_nodes,
                            },
                            description="Query resource with different identity",
                        ),
                    ],
                )
            )

        return hypotheses

    @staticmethod
    def _extract_param_name(statement: str) -> str | None:
        """Extract param name from "input('name', location=...)" statement."""
        import re
        m = re.search(r"input\('([^']+)'", statement)
        return m.group(1) if m else None

    @staticmethod
    def _extract_param_location(statement: str) -> str:
        """Extract location from "location='...'" in statement."""
        import re
        m = re.search(r"location='([^']+)'", statement)
        return m.group(1) if m else "query"

    def _is_duplicate(self, hyp: Hypothesis) -> bool:
        return any(
            existing.property_id == hyp.property_id
            and existing.statement == hyp.statement
            for existing in self._hypotheses.values()
        )

    @property
    def hypotheses(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def get_pending(self) -> list[Hypothesis]:
        """Get pending hypotheses sorted by priority (HIGH first)."""
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        pending = [
            h
            for h in self._hypotheses.values()
            if h.status == HypothesisStatus.PENDING
        ]
        return sorted(pending, key=lambda h: priority_order.get(h.priority, 3))
