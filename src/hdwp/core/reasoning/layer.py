# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    HYPOTHESIS_AMBIGUOUS,
    HYPOTHESIS_GENERATED,
    HYPOTHESIS_STATUS_CHANGED,
    PROPERTY_INFERRED,
    HDWPEvent,
)
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    generate_id,
)

if TYPE_CHECKING:
    from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.core.model.invariant_store import InvariantStore
    from hdwp.plugins.registry import PluginRegistry
    from hdwp.store.repository import Repository

logger = structlog.get_logger()


class StrategyDepth(str, Enum):
    PASSIVE = "PASSIVE"
    SHALLOW = "SHALLOW"
    STANDARD = "STANDARD"
    DEEP = "DEEP"


class HypothesisContext:
    __slots__ = (
        "causal_properties",
        "endpoint_path",
        "observed_values",
        "parameter_name",
        "parameter_type",
        "response_fields",
        "tech_stack",
        "threat_score",
    )

    def __init__(
        self,
        endpoint_path: str = "",
        parameter_name: str = "",
        parameter_type: str = "string",
        tech_stack: list[str] | None = None,
        threat_score: float = 0.0,
        observed_values: list[str] | None = None,
        response_fields: list[str] | None = None,
        causal_properties: list[str] | None = None,
    ) -> None:
        self.endpoint_path = endpoint_path
        self.parameter_name = parameter_name
        self.parameter_type = parameter_type
        self.tech_stack = tech_stack or []
        self.threat_score = threat_score
        self.observed_values = observed_values or []
        self.response_fields = response_fields or []
        self.causal_properties = causal_properties or []


class StrategySelector:
    def select(self, threat_score: float) -> StrategyDepth:
        if threat_score > 0.8:
            return StrategyDepth.DEEP
        if threat_score > 0.5:
            return StrategyDepth.STANDARD
        if threat_score > 0.2:
            return StrategyDepth.SHALLOW
        return StrategyDepth.PASSIVE


class AdaptiveSpecGenerator:
    _DB_SPECIFIC_PAYLOADS: ClassVar[dict[str, list[str]]] = {
        "postgresql": ["1 AND pg_sleep(3)=0", "1; SELECT pg_sleep(3)--"],
        "mysql": ["1 AND SLEEP(3)", "1; SELECT SLEEP(3)--"],
        "oracle": ["1 AND DBMS_LOCK.SLEEP(3)=0", "1 AND 1=UTL_INADDR.GET_HOST_ADDRESS('sleep3')"],
        "mssql": ["1; WAITFOR DELAY '0:0:3'--", "1 AND 1=(SELECT 1 FROM (SELECT SLEEP(3))t)"],
        "sqlite": ["1 AND 1=randomblob(100000000)", "1; SELECT CASE WHEN 1=1 THEN randomblob(100000000) END--"],
    }

    _NUMERIC_PAYLOADS: ClassVar[list[str]] = [
        "0", "-1", "99999999", "0.001",
        "1 OR 1=1", "1 AND 1=2",
    ]

    _STRING_PAYLOADS: ClassVar[list[str]] = [
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "<script>alert(1)</script>",
        "{{7*7}}", "${7*7}",
    ]

    def generate(self, ctx: HypothesisContext, depth: StrategyDepth) -> list[str]:
        payloads: list[str] = []

        detected_db = self._detect_db(ctx.tech_stack)
        if detected_db and detected_db in self._DB_SPECIFIC_PAYLOADS:
            payloads.extend(self._DB_SPECIFIC_PAYLOADS[detected_db])

        if ctx.parameter_type in ("integer", "float"):
            payloads.extend(self._NUMERIC_PAYLOADS)
        else:
            payloads.extend(self._STRING_PAYLOADS)

        if depth == StrategyDepth.PASSIVE:
            return payloads[:2]
        if depth == StrategyDepth.SHALLOW:
            return payloads[:4]
        if depth == StrategyDepth.STANDARD:
            return payloads[:6]
        return payloads

    def _detect_db(self, tech_stack: list[str]) -> str | None:
        for tag in tech_stack:
            tag_lower = tag.lower()
            for db in ("postgresql", "mysql", "oracle", "mssql", "sqlite"):
                if db in tag_lower:
                    return db
        return None


class ContextualHypothesisEngine:
    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable[[], ApplicationModelData | None] | None = None,
        plugin_registry: PluginRegistry | None = None,
        repository: Repository | None = None,
        prioritizer: HypothesisPrioritizer | None = None,
        llm_layer: LLMLayerProtocol | None = None,
        threat_model_accessor: Callable[[], dict[str, float]] | None = None,
        invariant_store: InvariantStore | None = None,
    ) -> None:
        self._bus = bus
        self._model_accessor = model_accessor
        self._plugin_registry = plugin_registry
        self._repository = repository
        self._prioritizer = prioritizer
        self._llm_layer = llm_layer
        self._threat_model_accessor = threat_model_accessor
        self._invariant_store = invariant_store

        self._hypotheses: list[Hypothesis] = []
        self._seen_keys: set[tuple[str, str, str]] = set()
        self._strategy_selector = StrategySelector()
        self._spec_generator = AdaptiveSpecGenerator()

        self._bandit: Any = None
        try:
            from hdwp.core.hypothesis.bandit import HypothesisBandit
            self._bandit = HypothesisBandit()
        except ImportError:
            pass

        bus.on(PROPERTY_INFERRED, self._on_property_inferred)
        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)
        bus.on(FINDING_REFUTED, self._on_finding_refuted)
        bus.on(HYPOTHESIS_AMBIGUOUS, self._on_hypothesis_ambiguous)
        bus.on(HYPOTHESIS_STATUS_CHANGED, self._on_hypothesis_status_changed)

    @property
    def hypotheses(self) -> list[Hypothesis]:
        return list(self._hypotheses)

    @property
    def bandit(self) -> Any:
        return self._bandit

    def get_pending(self) -> list[Hypothesis]:
        pending = [h for h in self._hypotheses if h.status == HypothesisStatus.PENDING]
        if self._bandit and pending:
            try:
                return self._bandit.sort(pending)
            except Exception as exc:  # noqa: BLE001
                logger.warning("contextual_hyp.bandit_sort_failed", error=str(exc))
        return pending

    def _build_context(self, endpoint_path: str, param_name: str = "") -> HypothesisContext:
        model = self._model_accessor() if self._model_accessor else None
        threat_score = 0.0
        if self._threat_model_accessor:
            scores = self._threat_model_accessor()
            threat_score = scores.get(endpoint_path, 0.0)

        tech_stack: list[str] = []
        param_type = "string"
        observed_values: list[str] = []
        response_fields: list[str] = []

        if model:
            tech_stack = list(model.tech_stack)
            for p in model.parameters:
                if p.name == param_name:
                    param_type = p.type_inferred
                    break
            corpus = model.response_corpus.get(endpoint_path, {})
            for role_bodies in corpus.values():
                for body in role_bodies:
                    if isinstance(body, dict):
                        response_fields.extend(body.keys())

        return HypothesisContext(
            endpoint_path=endpoint_path,
            parameter_name=param_name,
            parameter_type=param_type,
            tech_stack=tech_stack,
            threat_score=threat_score,
            observed_values=observed_values,
            response_fields=list(set(response_fields)),
        )

    def _add_hypothesis(self, hyp: Hypothesis) -> bool:
        key = self._dedup_key(hyp)
        if key in self._seen_keys:
            return False
        self._seen_keys.add(key)
        self._hypotheses.append(hyp)
        return True

    def _dedup_key(self, hyp: Hypothesis) -> tuple[str, str, str]:
        exps = hyp.required_experiments
        if not exps:
            return (hyp.statement, "", "")
        exp = exps[0]
        endpoint = exp.mutation_params.get("endpoint_path", exp.mutation_params.get("target_endpoint", ""))
        param = exp.mutation_params.get("parameter_name", "")
        return (endpoint, exp.mutation_type, param)

    async def _on_property_inferred(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        prop_type = payload.get("type", "")
        model_nodes = payload.get("model_nodes", [])
        prop_id = payload.get("id", generate_id("PROP"))

        model = self._model_accessor() if self._model_accessor else None
        if not model:
            return

        if self._plugin_registry:
            for plugin in self._plugin_registry.list_enabled():
                try:
                    plugin_hyps = plugin.generate_hypotheses(model)
                    for h in plugin_hyps:
                        if self._add_hypothesis(h):
                            await self._emit_hypothesis(h)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("contextual_hyp.plugin_failed", error=str(exc))

        for node_id in model_nodes:
            for ep in model.endpoints:
                if ep.id == node_id or ep.path == node_id:
                    ctx = self._build_context(ep.path)
                    depth = self._strategy_selector.select(ctx.threat_score)

                    for param_id in ep.parameters:
                        for p in model.parameters:
                            if p.id == param_id:
                                param_ctx = self._build_context(ep.path, p.name)
                                payloads = self._spec_generator.generate(param_ctx, depth)

                                hyp = Hypothesis(
                                    source_plugin="contextual_hypothesis_engine",
                                    property_id=prop_id,
                                    statement=f"Contextual test: {prop_type} on {ep.path} param {p.name}",
                                    property_type=prop_type,
                                    priority="HIGH" if ctx.threat_score > 0.5 else "MEDIUM",
                                    required_experiments=[
                                        ExperimentSpec(
                                            mutation_type="field_injection",
                                            base_request=NormalizedRequest(method="GET", url=ep.path),
                                            mutation_params={
                                                "endpoint_path": ep.path,
                                                "parameter_name": p.name,
                                                "parameter_location": p.location,
                                                "payloads": payloads,
                                                "strategy_depth": depth.value,
                                            },
                                        )
                                    ],
                                )
                                if self._add_hypothesis(hyp):
                                    await self._emit_hypothesis(hyp)
                                break

    async def _on_finding_confirmed(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        if self._bandit:
            try:
                proof = payload.get("proof", {}) or {}
                mutation_type = proof.get("mutation_type", "unknown")
                # Résoudre property_type depuis l'hypothèse stockée
                hyp_id = payload.get("hypothesis_id", "")
                hyp = next((h for h in self._hypotheses if h.id == hyp_id), None)
                property_type = (hyp.property_type or "unknown") if hyp else "unknown"
                self._bandit.update(property_type, mutation_type, "CONFIRMED")
            except Exception as exc:  # noqa: BLE001
                logger.warning("contextual_hyp.bandit_update_failed", error=str(exc))

        await self._generate_follow_up_confirmed(payload)

    async def _on_finding_refuted(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        if self._bandit:
            try:
                proof = payload.get("proof", {}) or {}
                mutation_type = proof.get("mutation_type", "unknown")
                hyp_id = payload.get("hypothesis_id", "")
                hyp = next((h for h in self._hypotheses if h.id == hyp_id), None)
                property_type = (hyp.property_type or "unknown") if hyp else "unknown"
                self._bandit.update(property_type, mutation_type, "REFUTED")
            except Exception as exc:  # noqa: BLE001
                logger.warning("contextual_hyp.bandit_update_failed", error=str(exc))

    async def _on_hypothesis_ambiguous(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return

        if self._bandit:
            try:
                mutation_type = payload.get("mutation_type", "unknown")
                hyp_id = payload.get("hypothesis_id", "")
                hyp = next((h for h in self._hypotheses if h.id == hyp_id), None)
                property_type = (hyp.property_type or "unknown") if hyp else "unknown"
                self._bandit.update(property_type, mutation_type, "INSUFFICIENT_DATA")
            except Exception as exc:  # noqa: BLE001
                logger.warning("contextual_hyp.bandit_update_failed", error=str(exc))

    async def _on_hypothesis_status_changed(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return
        hyp_id = payload.get("id", "")
        new_status_str = payload.get("new_status", "")
        if not hyp_id or not new_status_str:
            return
        try:
            new_status = HypothesisStatus(new_status_str)
        except ValueError:
            return
        for h in self._hypotheses:
            if h.id == hyp_id:
                h.status = new_status
                break

    async def _generate_follow_up_confirmed(self, payload: dict) -> None:
        """Génère des hypothèses de suivi après un finding confirmé."""
        cwe = payload.get("cwe_id", "")
        proof = payload.get("proof", {}) or {}
        affected = payload.get("affected_endpoints", [])
        mutation_type = proof.get("mutation_type", "")
        winning_req = proof.get("winning_request") or {}
        endpoint_path = affected[0] if affected else winning_req.get("url", "")
        winning_method = (winning_req.get("method") or "GET").upper()
        prop_id = payload.get("property_id") or generate_id("PROP")

        if not endpoint_path:
            return

        follow_ups: list[Hypothesis] = []

        # SQLi (CWE-89) : escalade vers payloads avancés
        if cwe.endswith("-89") or mutation_type == "field_injection":
            for payload_str, desc in [
                ("1 UNION SELECT null,null,null--", "union-based SQLi"),
                ("1 AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--", "error-based SQLi"),
                ("1; SELECT pg_sleep(3)--", "stacked query + blind timing"),
                ("1 AND SLEEP(3)--", "blind timing MySQL"),
            ]:
                follow_ups.append(Hypothesis(
                    source_plugin="contextual_hypothesis_engine.followup",
                    property_id=prop_id,
                    property_type="integrity",
                    statement=f"SQLi escalation ({desc}) on {endpoint_path}",
                    priority="HIGH",
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method=winning_method, url=endpoint_path),
                            mutation_params={
                                "endpoint_path": endpoint_path,
                                "payloads": [payload_str],
                                "strategy_depth": "DEEP",
                                "followup_variant": desc,
                            },
                        )
                    ],
                ))

        # BOLA / IDOR (CWE-639, CWE-284) : variantes d'ID
        elif cwe.endswith("-639") or cwe.endswith("-284") or mutation_type in ("identity_swap", "object_ref_change"):
            for id_val in ("0", "-1", "999999"):
                follow_ups.append(Hypothesis(
                    source_plugin="contextual_hypothesis_engine.followup",
                    property_id=prop_id,
                    property_type="authorization",
                    statement=f"BOLA ID variant {id_val} on {endpoint_path}",
                    priority="HIGH",
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="object_ref_change",
                            base_request=NormalizedRequest(method=winning_method, url=endpoint_path),
                            mutation_params={
                                "endpoint_path": endpoint_path,
                                "target_id": id_val,
                                "followup_variant": f"id_{id_val}",
                            },
                        )
                    ],
                ))

        for hyp in follow_ups:
            if self._add_hypothesis(hyp):
                await self._emit_hypothesis(hyp)

    async def _emit_hypothesis(self, hyp: Hypothesis) -> None:
        if self._repository:
            try:
                await self._repository.save_hypothesis(hyp)
            except Exception as exc:  # noqa: BLE001
                logger.warning("contextual_hyp.save_failed", error=str(exc))

        await self._bus.emit(
            HYPOTHESIS_GENERATED,
            hyp.model_dump(),
            source="contextual_hypothesis_engine",
        )
