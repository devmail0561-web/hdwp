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

import httpx
import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.context.loader import ContextLoader, EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.engine import ExperimentEngine
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.hypothesis.engine import HypothesisEngine
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
        hyp_engine: HypothesisEngine,
        exp_engine: ExperimentEngine,
        oracle: SemanticOracle,
        session_manager: SessionManager,
        repository: Repository,
        report_engine: ReportEngine,
        knowledge_base: KnowledgeBase | None = None,
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
    ) -> HDWPEngine:
        """Logique commune : initialise tous les composants depuis un context + bus."""
        from hdwp.core.paths import evidence_db_url

        scope_guard = ScopeGuard(context)

        effective_db_url = db_url or evidence_db_url(context.session_id)
        engine_db = await init_db(effective_db_url)
        repository = Repository(engine_db)

        app_model = ApplicationModel(bus)

        # Plugin registry
        registry = PluginRegistry()
        registry.discover()
        enabled = plugin_ids or context.config.plugins.enabled
        for pid in enabled:
            registry.enable(pid)

        # KnowledgeBase : charger les poids adAPes avant de creer le prioritizer
        from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
        from hdwp.core.knowledge.base import DEFAULT_KB_PATH, KnowledgeBase

        kb_path = context.config.options.knowledge_db or DEFAULT_KB_PATH
        kb = KnowledgeBase(db_path=kb_path)
        adapted_weights = await kb.get_adapted_weights()
        prioritizer = HypothesisPrioritizer.with_weights(adapted_weights)
        session_count = await kb.get_session_count()
        log.info("engine.knowledge_loaded", kb_path=str(kb_path), sessions=session_count)

        # Composants de raisonnement (s'abonnent au bus a l'initialisation)
        SecurityPropertyEngine(bus, plugin_registry=registry)
        hyp_engine = HypothesisEngine(
            bus,
            model_accessor=app_model.snapshot,
            plugin_registry=registry,
            repository=repository,
            prioritizer=prioritizer,
        )
        from hdwp.core.llm.layer import create_llm_layer

        llm_layer = create_llm_layer(context.config.llm)
        oracle = SemanticOracle(bus, repository, llm_layer=llm_layer)
        PassiveFindingEngine(bus, repository)
        report_engine = ReportEngine(bus, repository)

        # FSM Learner: s'abonne a observation.raw, publie fsm.updated
        from hdwp.core.state_machine.learner import StateMachineLearner

        StateMachineLearner(bus)

        obs_engine = ObservationEngine(bus, context, scope_guard)

        rate_limiter = TokenBucket.from_rpm(context.config.options.max_requests_per_minute)
        session_manager = SessionManager(context.config.roles)

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

        def _cred_handler(event: _HDWPEvent) -> None:
            asyncio.create_task(_on_credentials_captured(event, session_manager))

        bus.on(CREDENTIALS_CAPTURED, _cred_handler)

        exp_engine = ExperimentEngine(
            bus=bus,
            scope_guard=scope_guard,
            session_manager=session_manager,
            rate_limiter=rate_limiter,
            model_accessor=app_model.snapshot,
            corpus_accessor=app_model.get_all_corpus,
        )

        return cls(
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
        )

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
    ) -> HDWPEngine:
        """Variante pour le TUI : accepte un bus et un context deja crees.
        Le bus est celui du proxy, partage avec le moteur."""
        return await cls._init_components(context, bus, db_url, plugin_ids)

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

        # Phase 2 : raisonnement + experiences
        pending = self._hyp_engine.get_pending()
        log.info("engine.hypotheses_ready", count=len(pending))

        if pending:
            await self._exp_engine.run_pending(pending)
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
