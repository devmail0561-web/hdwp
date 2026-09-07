# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
HDWPEngine: orchestre tous les composants pour une campagne d'analyse complete.

Sequencer MVP (mode sequentiel) :
  1. Charger le contexte (ContextLoader)
  2. Initialiser l'Event Bus et les composants
  3. Crawl complet (ObservationEngine)
  4. Attendre model_confidence >= 0.3 (ApplicationModel.is_ready)
  5. Executer les experiences sur les hypotheses generees (ExperimentEngine)
  6. Retourner les findings confirmes

Les composants communiquent via le bus : aucun appel direct entre eux.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from hdwp.core.knowledge.base import KnowledgeBase

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.context.loader import ContextLoader, EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.engine import ExperimentEngine
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.reasoning.layer import ContextualHypothesisEngine
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import Finding
from hdwp.core.observation.engine import ObservationEngine
from hdwp.core.oracle.engine import SemanticOracle
from hdwp.core.oracle.passive_engine import PassiveFindingEngine
from hdwp.core.property_engine.engine import SecurityPropertyEngine
from hdwp.core.report.engine import ReportEngine
from hdwp.plugins.registry import PluginRegistry
from hdwp.store.database import init_db
from hdwp.store.repository import Repository

log = structlog.get_logger()


async def _on_credentials_captured(
    event: Any, session_manager: SessionManager
) -> None:
    """Handle credentials.captured bus event: add captured role to SessionManager."""
    from hdwp.core.context.config_schema import CredentialConfig, RoleConfig

    data = event.payload
    if not isinstance(data, dict):
        return
    role = RoleConfig(
        name=data.get("role_name", "captured"),
        credentials=CredentialConfig(
            type=data.get("token_type", "bearer"),  # type: ignore[arg-type]
            token=data.get("token_value", ""),
        ),
    )
    await session_manager.add_role(role)
    log.info(
        "engine.credential_captured",
        role=data.get("role_name"),
        url=data.get("source_url", ""),
    )


class HDWPEngine:
    """
    Point d'entree haut niveau pour lancer une campagne HDWP.

    Usage::

        engine = await HDWPEngine.create(context_path)
        findings = await engine.run()
        await engine.close()

    Ou via context manager::

        async with HDWPEngine.create(context_path) as engine:
            findings = await engine.run()
    """

    def __init__(
        self,
        context: EngineContext,
        bus: AsyncEventBus,
        app_model: ApplicationModel,
        obs_engine: ObservationEngine,
        hyp_engine: ContextualHypothesisEngine,
        exp_engine: ExperimentEngine,
        oracle: SemanticOracle,
        session_manager: SessionManager,
        repository: Repository,
        report_engine: ReportEngine,
        knowledge_base: KnowledgeBase | None = None,
        prop_engine: SecurityPropertyEngine | None = None,
        llm_layer: Any | None = None,
    ) -> None:
        self._context = context
        self._bus = bus
        self._app_model = app_model
        self._obs_engine = obs_engine
        self._hyp_engine = hyp_engine
        self._exp_engine = exp_engine
        self._oracle = oracle
        self._session_manager = session_manager
        self._repository = repository
        self._report_engine = report_engine
        self._kb = knowledge_base
        self._prop_engine = prop_engine
        self._llm_layer = llm_layer
        self._adaptive_payload_engine: Any | None = None

        from hdwp.core.attack_graph.planner import AttackGraphPlanner
        self._chain_engine = AttackGraphPlanner(
            bus=bus,
            model_accessor=app_model.snapshot,
            flow_map_accessor=app_model.get_flow_map,
            repository=repository,
            target_url=context.base_url,
            roles=context.config.roles,
            session_id=context.session_id,
        )

    @property
    def report_engine(self) -> ReportEngine:
        return self._report_engine

    @classmethod
    async def _init_components(
        cls,
        context: EngineContext,
        bus: AsyncEventBus,
        db_url: str | None = None,
        plugin_ids: list[str] | None = None,
        proxy_url: str | None = None,
    ) -> HDWPEngine:
        """Logique commune : initialise tous les composants depuis un context + bus."""
        from hdwp.core.paths import evidence_db_url

        scope_guard = ScopeGuard(context)

        effective_db_url = db_url or evidence_db_url(context.session_id)
        engine_db = await init_db(effective_db_url)
        repository = Repository(engine_db)

        app_model = ApplicationModel(bus)

        # V3 InvariantStore: inductive invariant learning
        from hdwp.core.model.invariant_store import InvariantStore

        invariant_store = InvariantStore(bus)

        # Plugin registry
        registry = PluginRegistry()
        registry.discover()
        disabled_ids = set(context.config.plugins.disabled)
        if plugin_ids:
            for pid in plugin_ids:
                registry.enable(pid)
        elif context.config.plugins.enabled:
            for pid in context.config.plugins.enabled:
                registry.enable(pid)
        else:
            # enabled=[] → activer tous les plugins découverts sauf ceux explicitement désactivés
            for p in registry.list_all():
                if p.id not in disabled_ids:
                    registry.enable(p.id)

        # Enregistrer les mutations custom des plugins
        from hdwp.core import mutation_registry

        for plugin in registry.list_enabled():
            for mut_spec in plugin.register_mutations():
                mutation_registry.register(**mut_spec)

        # KnowledgeBase : charger les poids adaptés avant de créer le prioritizer
        from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
        from hdwp.core.knowledge.base import DEFAULT_KB_PATH, KnowledgeBase, classify_target

        kb_path = context.config.options.knowledge_db or DEFAULT_KB_PATH
        kb = KnowledgeBase(db_path=kb_path)
        url_target_type = classify_target(context.base_url)
        tuning = context.config.tuning
        # Fusionner les poids d'impact du TuningConfig avec les poids KB adaptés
        adapted_weights = await kb.get_adapted_weights(target_type=url_target_type)
        if tuning.impact_weights:
            adapted_weights.update(tuning.impact_weights)
        prioritizer = HypothesisPrioritizer.with_weights(
            adapted_weights,
            high_threshold=tuning.priority_high_threshold,
            medium_threshold=tuning.priority_medium_threshold,
        )
        confidence_weights = await kb.get_confidence_weights()
        app_model.set_confidence_weights(confidence_weights)
        session_count = await kb.get_session_count()
        log.info(
            "engine.knowledge_loaded",
            kb_path=str(kb_path),
            sessions=session_count,
            target_type=url_target_type,
        )

        # LLM layer (créé AVANT HypothesisEngine et ObservationEngine pour injection)
        from hdwp.core.llm.layer import create_llm_layer

        llm_layer = create_llm_layer(context.config.llm)

        # KB stats for adaptive inference confidence (aggregated across target_types)
        raw_stats = await kb.get_stats()
        kb_stats: dict[tuple[str, str], dict[str, float]] = {}
        for s in raw_stats:
            key = (s["property_type"], s["mutation_type"])
            if key not in kb_stats:
                kb_stats[key] = {"confirmed_rate": 0.0, "total": 0}
            prev = kb_stats[key]
            prev_total = prev["total"]
            new_total = prev_total + s["total"]
            if new_total > 0:
                prev["confirmed_rate"] = (
                    prev["confirmed_rate"] * prev_total + s["confirmed_rate"] * s["total"]
                ) / new_total
            prev["total"] = new_total

        # V3 ThreatModelEngine: dynamic threat scoring per endpoint
        from hdwp.core.threat.engine import ThreatModelEngine

        threat_engine = ThreatModelEngine(
            bus=bus,
            model_accessor=app_model.snapshot,
            flow_map_accessor=app_model.get_flow_map,
        )

        from hdwp.core.property_engine.inference_registry import InferenceRegistry

        inference_reg = InferenceRegistry.default_with_kb_stats(kb_stats)
        prop_engine = SecurityPropertyEngine(bus, plugin_registry=registry, inference_registry=inference_reg)
        hyp_engine = ContextualHypothesisEngine(
            bus,
            model_accessor=app_model.snapshot,
            plugin_registry=registry,
            repository=repository,
            prioritizer=prioritizer,
            llm_layer=llm_layer,
            threat_model_accessor=lambda: threat_engine.scores,
            invariant_store=invariant_store,
        )
        oracle = SemanticOracle(
            bus, repository, llm_layer=llm_layer,
            model_accessor=app_model.snapshot,
            tuning=tuning,
        )
        oracle.invariant_store = invariant_store

        # V3 CrossRoleDiffEngine: multi-role response comparison
        from hdwp.core.oracle.crossrole_diff import CrossRoleDiffEngine

        CrossRoleDiffEngine(bus, model_accessor=app_model.snapshot)

        # V3 TemporalAnomalyDetector: blind injection timing detection
        from hdwp.core.oracle.temporal_detector import TemporalAnomalyDetector

        TemporalAnomalyDetector(bus)

        PassiveFindingEngine(bus, repository)
        report_engine = ReportEngine(bus, repository)

        # AmbiguityResolver : relance des expériences de désambiguïsation sur verdict AMBIGUOUS
        from hdwp.core.oracle.ambiguity_resolver import AmbiguityResolver
        AmbiguityResolver(bus, repository)

        # FSM Learner: s'abonne a observation.raw, publie fsm.updated
        from hdwp.core.state_machine.learner import StateMachineLearner

        StateMachineLearner(bus)

        obs_engine = ObservationEngine(bus, context, scope_guard, llm_layer=llm_layer, proxy_url=proxy_url)

        # Configurer le proxy global pour tous les clients HTTP créés via http_client.build_client()
        # proxy_url (CLI --proxy) prime sur tor_proxy (config file)
        from hdwp.core import http_client as _http_client
        effective_proxy = proxy_url or context.config.options.tor_proxy
        _http_client.configure(effective_proxy)

        # Validate required config attributes
        if not hasattr(context.config, "roles") or context.config.roles is None:
            raise ValueError("context.config.roles is required but missing or None")

        rate_limiter = TokenBucket.from_rpm(context.config.options.max_requests_per_minute)
        session_manager = SessionManager(context.config.roles, proxy_url=effective_proxy)

        # Initialize clients via session manager context manager
        async with session_manager as sm:
            # Pre-acquire OAuth2 tokens
            for role in context.config.roles:
                if role.credentials and role.credentials.type in ("oauth2_password", "oauth2_client_credentials"):
                    try:
                        token = await sm._oauth_clients[role.name].get_token()
                        role.credentials.token = token
                        log.info("engine.oauth2_token_preacquired", role=role.name)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("engine.oauth2_token_failed", role=role.name, error=str(exc))

        # Wire credential capture
        from hdwp.core.bus.events import CREDENTIALS_CAPTURED
        from hdwp.core.bus.events import HDWPEvent as _HDWPEvent

        async def _cred_handler(event: _HDWPEvent) -> None:
            await _on_credentials_captured(event, session_manager)

        bus.on(CREDENTIALS_CAPTURED, _cred_handler)

        exp_engine = ExperimentEngine(
            bus=bus,
            scope_guard=scope_guard,
            session_manager=session_manager,
            rate_limiter=rate_limiter,
            model_accessor=app_model.snapshot,
            corpus_accessor=app_model.get_all_corpus,
            max_concurrent=context.config.options.max_concurrent_experiments,
        )

        # V3 AdaptivePayloadEngine: real-time signal classification + WAF bypass
        from hdwp.core.experiment.adaptive_payload import AdaptivePayloadEngine

        adaptive_engine = AdaptivePayloadEngine(bus)

        engine = cls(
            context=context,
            bus=bus,
            app_model=app_model,
            obs_engine=obs_engine,
            hyp_engine=hyp_engine,
            exp_engine=exp_engine,
            oracle=oracle,
            session_manager=session_manager,
            repository=repository,
            report_engine=report_engine,
            knowledge_base=kb,
            prop_engine=prop_engine,
            llm_layer=llm_layer,
        )
        engine._adaptive_payload_engine = adaptive_engine

        return engine

    @classmethod
    async def create(
        cls,
        context_path: Path,
        db_url: str | None = None,
        plugin_ids: list[str] | None = None,
    ) -> HDWPEngine:
        """Charge un fichier YAML puis delegue a _init_components."""
        context = ContextLoader.load(context_path)
        bus = AsyncEventBus()
        return await cls._init_components(context, bus, db_url, plugin_ids)

    @classmethod
    async def create_from_context(
        cls,
        context: EngineContext,
        bus: AsyncEventBus,
        db_url: str | None = None,
        plugin_ids: list[str] | None = None,
        proxy_url: str | None = None,
    ) -> HDWPEngine:
        """Variante pour le TUI : accepte un bus et un context deja crees.
        Le bus est celui du proxy, partage avec le moteur."""
        return await cls._init_components(context, bus, db_url, plugin_ids, proxy_url=proxy_url)

    async def run(self) -> list[Finding]:
        """Lance le pipeline complet et retourne les findings confirmes."""
        log.info(
            "engine.start",
            target=self._context.base_url,
            session=self._context.session_id,
        )

        # Phase 1a : pre-alimentation depuis spec OpenAPI / endpoints manuels
        seeded = await self._obs_engine.seed_from_spec()
        if seeded > 0:
            log.info("engine.openapi_seeded", observations=seeded)
            await self._bus.drain()

        # Phase 1b : crawl actif
        await self._obs_engine.start()
        await self._bus.drain()

        # Phase 1c : auto-registration si moins de 2 roles authentifies
        if self._context.config.options.allow_write:
            auth_roles = [
                r for r in self._context.config.roles if r.credentials is not None
            ]
            if len(auth_roles) < 2:
                from hdwp.core.context.scope_guard import ScopeGuard as _ScopeGuard
                from hdwp.core.observation.auto_registrar import AutoRegistrar

                _sg = _ScopeGuard(self._context)
                registrar = AutoRegistrar(
                    session_manager=self._session_manager,
                    scope_guard=_sg,
                    context=self._context,
                )
                new_roles = await registrar.try_register_test_accounts()
                for role in new_roles:
                    await self._session_manager.add_role(role)
                    log.info("engine.auto_registered_role", role=role.name)
                if new_roles:
                    await self._bus.drain()
                self._auto_registrar: AutoRegistrar | None = registrar
            else:
                self._auto_registrar = None
        else:
            self._auto_registrar = None

        log.info(
            "engine.observation_done",
            model_confidence=round(self._app_model.model_confidence, 2),
            is_ready=self._app_model.is_ready,
            endpoints=len(self._app_model.snapshot().endpoints),
        )

        if not self._app_model.is_ready:
            log.warning(
                "engine.low_coverage",
                confidence=round(self._app_model.model_confidence, 2),
                msg="Le modele a peu de couverture -- les hypotheses peuvent etre limitees",
            )

        # Phase 2 vague 1 : experiments sur les hypothèses générées pendant le crawl.
        # Le corpus est complet (crawl terminé), pas de risque de concurrence.
        pending_v1 = self._hyp_engine.get_pending()
        log.info("engine.experiments_v1", count=len(pending_v1))

        if pending_v1:
            await self._exp_engine.run_pending(pending_v1)
            await self._bus.drain()

        # Phase 1b-bis : scan des versions de bibliothèques JS/CSS (OWASP A06:2021)
        try:
            from hdwp.core.observation.version_scanner import scan_and_emit as _vs_scan
            vs_count = await _vs_scan(
                script_urls=self._obs_engine.collected_script_urls,
                script_contents=self._obs_engine.collected_script_contents,
                script_pages=self._obs_engine.collected_script_pages,
                bus=self._bus,
                repository=self._repository,
                model_accessor=self._app_model.snapshot,
            )
            if vs_count > 0:
                log.info("engine.version_scan_done", findings=vs_count)
                await self._bus.drain()
        except Exception as exc:
            log.warning("engine.version_scan_failed", error=str(exc))

        # Phase 2 vague 2 : nouvelles hypothèses générées par le version scan ou l'auto-registration.
        pending_v2 = self._hyp_engine.get_pending()
        log.info("engine.experiments_v2", count=len(pending_v2))

        if pending_v2:
            await self._exp_engine.run_pending(pending_v2)
            await self._bus.drain()

        # Phase 3 : chaînes d'attaque (si 2+ findings confirmés)
        if self._chain_engine.has_pending_chains():
            log.info("engine.chains_start")
            await self._chain_engine.run_pending_chains(self._exp_engine)
            await self._bus.drain()

        # ── Mode continu : itérations supplémentaires jusqu'à épuisement ou timeout ──
        if self._context.config.options.continuous:
            import time
            time_limit = self._context.config.options.scan_time_limit_minutes
            deadline = time.monotonic() + time_limit * 60 if time_limit > 0 else float("inf")
            iteration = 0
            # Injecter le model_accessor dans obs_engine pour rescan
            self._obs_engine._model_accessor = self._app_model.snapshot
            while time.monotonic() < deadline:
                pending = self._hyp_engine.get_pending()
                if not pending:
                    log.info("engine.continuous_complete", iterations=iteration)
                    break
                iteration += 1
                log.info("engine.continuous_iteration", iteration=iteration, pending=len(pending))

                # Re-observer les endpoints connus pour détecter les changements d'état
                await self._obs_engine.rescan_known_endpoints()
                await self._bus.drain()

                await self._exp_engine.run_pending(pending)
                await self._bus.drain()

                if self._chain_engine.has_pending_chains():
                    await self._chain_engine.run_pending_chains(self._exp_engine)
                    await self._bus.drain()

        # Recuperer les findings confirmes
        findings = await self._repository.list_findings(status="CONFIRMED")
        log.info("engine.done", findings_count=len(findings))

        # Mettre a jour la KnowledgeBase avec les resultats de cette session
        if self._kb is not None and findings:
            await self._kb.record_session(
                findings=findings,
                session_id=self._context.session_id,
                target_url=self._context.base_url,
                model_snapshot=self._app_model.snapshot(),
            )
            sessions = await self._kb.get_session_count()
            log.info("engine.knowledge_updated", sessions=sessions, findings=len(findings))

        return findings

    async def close(self) -> None:
        """Libere les ressources (sessions HTTP, KnowledgeBase, comptes de test)."""
        await self._session_manager.close_all()
        if self._kb is not None:
            await self._kb.close()
        if getattr(self, "_auto_registrar", None) is not None:
            await self._auto_registrar.cleanup()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
