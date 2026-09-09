# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ExperimentEngine: orchestrates hypothesis → concrete plans → HTTP execution → results.

For each pending hypothesis (HIGH priority first):
  1. RequestSelector resolves ConcreteExperimentPlans from the corpus
  2. MutationModule builds the mutated NormalizedRequest
  3. SessionManager provides the per-role httpx client
  4. baseline + mutation are executed (mutation is replayed once for reproducibility)
  5. experiment.result emitted for every result
  6. hypothesis.experiments_ready emitted when the full batch is done
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    HYPOTHESIS_EXPERIMENTS_READY,
    HYPOTHESIS_STATUS_CHANGED,
)
from hdwp.core.context.scope_guard import ScopeGuard, ScopeVerdict
from hdwp.core.experiment.mutation_module import MutationModule
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.request_selector import RequestSelector
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.experiment.temporal_module import TemporalModule
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentResult,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
)
from hdwp.core.observation.normalizer import normalize_response

log = structlog.get_logger()


class ExperimentEngine:
    """
    Receives PENDING hypotheses, executes experiments and publishes results.

    Two callables decouple the engine from the ApplicationModel object:
      model_accessor  — returns the current ApplicationModelData snapshot
      corpus_accessor — returns the full request corpus for RequestSelector
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
        rate_limiter: TokenBucket,
        model_accessor: Callable[[], ApplicationModelData | None],
        corpus_accessor: Callable[[], dict[str, list[tuple[str, NormalizedRequest]]]],
        max_concurrent: int = 3,
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._session_manager = session_manager
        self._rate_limiter = rate_limiter
        self._model_accessor = model_accessor
        self._corpus_accessor = corpus_accessor
        self._selector = RequestSelector()
        self._mutator = MutationModule()
        self._temporal = TemporalModule()
        self._results_buffer: dict[str, list[ExperimentResult]] = {}
        # Cache des baselines invalides (url, method, role) → True.
        # Partagé entre toutes les hypothèses : évite de retenter un endpoint
        # qui a déjà retourné 404/500/0 pour la même combinaison (url, method, role).
        self._invalid_baselines: set[tuple[str, str, str]] = set()
        # Semaphore: limite les expériences concurrentes pour ne pas flood la cible
        self._semaphore = asyncio.Semaphore(max_concurrent)
    async def run_pending(self, hypotheses: list[Hypothesis]) -> None:
        """Execute hypotheses en respectant la priorité HIGH-before-LOW.

        asyncio.gather créerait toutes les coroutines simultanément, permettant
        aux hypothèses LOW de voler les slots semaphore avant les HIGH.
        On utilise une queue de priorité pour que les slots soient toujours
        accordés aux hypothèses de plus haute priorité en attente.
        """
        if not hypotheses:
            return
        # hypotheses est déjà trié par priorité (HIGH en premier) par l'appelant.
        # On crée les tâches séquentiellement dans l'ordre pour que le semaphore
        # soit acquis dans l'ordre de soumission tant que les slots sont libres.
        tasks = []
        for hyp in hypotheses:
            task = asyncio.ensure_future(self._run_with_semaphore(hyp))
            tasks.append(task)
            # Céder le contrôle pour que les tâches HIGH déjà créées démarrent
            # et acquièrent le semaphore avant d'en créer de nouvelles.
            await asyncio.sleep(0)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, asyncio.CancelledError):
                raise r  # propager l'annulation — ne pas avaler silencieusement
            if isinstance(r, BaseException):
                log.warning("experiment.task_failed", task_index=i, error=str(r))

    async def _run_with_semaphore(self, hyp: Hypothesis) -> None:
        async with self._semaphore:
            await self._run_hypothesis(hyp)

    # Profondeur maximale des chaînes de follow-up pour éviter les boucles infinies
    _MAX_FOLLOWUP_DEPTH = 3

    async def _run_hypothesis(self, hyp: Hypothesis) -> None:
        from hdwp.core.experiment.condition_evaluator import evaluate_trigger

        model = self._model_accessor()
        if model is None:
            log.warning("experiment.no_model", hypothesis_id=hyp.id)
            return

        corpus = self._corpus_accessor()
        initial_plans = self._selector.select_for_hypothesis(hyp, model, corpus)
        if not initial_plans:
            log.warning("experiment.no_plans", hypothesis_id=hyp.id)
            return

        baseline_id: str | None = None
        experiment_ids: list[str] = []
        self._results_buffer[hyp.id] = []

        # Utiliser une deque pour supporter les follow-up plans ajoutés dynamiquement.
        # Chaque élément est (plan, depth) pour respecter MAX_FOLLOWUP_DEPTH.
        plan_queue: deque[tuple[ConcreteExperimentPlan, int]] = deque(
            (p, 0) for p in initial_plans
        )

        while plan_queue:
            plan, depth = plan_queue.popleft()

            # Rôle effectif pour les requêtes mutées selon le type de mutation
            mutation_role = (
                plan.target_role
                if plan.mutation_type in ("identity_swap", "privilege_escalation") and plan.target_role
                else plan.baseline_role
            )

            # ── baseline (legitimate access) ──────────────────────────
            _baseline_key = (plan.baseline_request.url, plan.baseline_request.method, plan.baseline_role)
            if _baseline_key in self._invalid_baselines:
                log.debug(
                    "experiment.baseline_cached_invalid",
                    hypothesis_id=hyp.id,
                    url=plan.baseline_request.url,
                    role=plan.baseline_role,
                )
                continue

            baseline = await self._execute(
                plan.baseline_request, hyp.id, plan.experiment_spec,
                role=plan.baseline_role,
            )
            baseline = baseline.model_copy(update={"is_baseline": True})
            # Abandonner le plan si la baseline est invalide (endpoint disparu, mauvais path).
            # Tester une mutation contre une baseline 404/500 pollue l'oracle et gaspille
            # des slots de rate-limiter sans valeur ajoutée.
            base_status = baseline.response_received.status_code if baseline.response_received else 0
            if base_status == 0:
                # Network failure: emit so callers observe the error, but skip mutation.
                log.warning(
                    "experiment.baseline_invalid_skip",
                    hypothesis_id=hyp.id,
                    url=plan.baseline_request.url,
                    status=base_status,
                )
                self._invalid_baselines.add(_baseline_key)
                self._results_buffer[hyp.id].append(baseline)
                await self._bus.emit(EXPERIMENT_RESULT, baseline.model_dump(), source="experiment_engine")
                continue
            if base_status in (404, 500, 502, 503):
                log.debug(
                    "experiment.baseline_invalid_skip",
                    hypothesis_id=hyp.id,
                    url=plan.baseline_request.url,
                    status=base_status,
                )
                self._invalid_baselines.add(_baseline_key)
                continue
            if baseline_id is None:
                baseline_id = baseline.id
            self._results_buffer[hyp.id].append(baseline)
            await self._bus.emit(EXPERIMENT_RESULT, baseline.model_dump(), source="experiment_engine")

            # ── race condition experiments (via TemporalModule) ───────────────
            if plan.mutation_type == "race_condition":
                client = self._session_manager.get_client(mutation_role)
                temporal_results = await self._temporal.run_race_condition(
                    client=client,
                    request=plan.baseline_request,
                    hypothesis_id=hyp.id,
                    spec=plan.experiment_spec,
                    concurrency=plan.experiment_spec.mutation_params.get("concurrency", 10),
                )
                for res in temporal_results:
                    experiment_ids.append(res.id)
                    self._results_buffer[hyp.id].append(res)
                    await self._bus.emit(EXPERIMENT_RESULT, res.model_dump(), source="experiment_engine")
                continue

            # ── mutation ──────────────────────────────────────────────
            mutated_req = self._mutator.apply(plan, self._session_manager)
            verdict = self._scope_guard.check(mutated_req.url, mutated_req.method)
            if verdict != ScopeVerdict.ALLOWED:
                log.warning(
                    "experiment.blocked",
                    url=mutated_req.url,
                    verdict=verdict.value,
                    hypothesis_id=hyp.id,
                )
                continue

            mutation = await self._execute(
                mutated_req, hyp.id, plan.experiment_spec, role=mutation_role,
            )
            experiment_ids.append(mutation.id)
            self._results_buffer[hyp.id].append(mutation)
            await self._bus.emit(EXPERIMENT_RESULT, mutation.model_dump(), source="experiment_engine")

            # ── follow-up adaptatif (évalué AVANT le replay) ─────────
            # Évaluer trigger_condition contre le résultat de mutation brut.
            # Si déclenché et profondeur < MAX, ajouter les follow-up specs à la queue.
            if (
                depth < self._MAX_FOLLOWUP_DEPTH
                and plan.experiment_spec.trigger_condition is not None
                and plan.experiment_spec.follow_up_specs
                and evaluate_trigger(plan.experiment_spec.trigger_condition, mutation)
            ):
                for follow_spec in plan.experiment_spec.follow_up_specs:
                    follow_plans = self._selector.select_for_spec(
                        follow_spec, hyp, model, corpus
                    )
                    for fp in follow_plans:
                        plan_queue.append((fp, depth + 1))
                log.debug(
                    "experiment.followup_triggered",
                    hypothesis_id=hyp.id,
                    depth=depth,
                    n_follow_ups=len(plan.experiment_spec.follow_up_specs),
                )

            # ── WAF bypass adaptatif ──────────────────────────────────
            # Si la mutation retourne un 403 et qu'un WAF est connu, générer des
            # follow-up specs avec encodages adaptés au WAF détecté.
            # _bypass_attempted empêche la récursion : un plan de bypass ne génère pas d'autres bypasses.
            if (
                depth < self._MAX_FOLLOWUP_DEPTH
                and mutation.response_received is not None
                and mutation.response_received.status_code in (403, 406)
                and model is not None
                and not plan.experiment_spec.mutation_params.get("_bypass_attempted")
            ):
                waf_tags = [t for t in model.tech_stack if t.startswith("waf:")]
                if waf_tags and "payload" in plan.experiment_spec.mutation_params:
                    try:
                        from hdwp.core.experiment.encoding_pipeline import (
                            build_bypass_experiment_specs,
                        )
                        from hdwp.core.model.schemas import ExperimentSpec
                        waf_tag = waf_tags[0]
                        bypass_params_list = build_bypass_experiment_specs(
                            original_payload=plan.experiment_spec.mutation_params["payload"],
                            mutation_params=dict(plan.experiment_spec.mutation_params),
                            waf_tag=waf_tag,
                            max_strategies=2,
                        )
                        for bypass_params in bypass_params_list:
                            bypass_spec = ExperimentSpec(
                                mutation_type=plan.experiment_spec.mutation_type,
                                base_request=plan.experiment_spec.base_request,
                                mutation_params={**bypass_params, "_bypass_attempted": True},
                                description=f"WAF bypass ({bypass_params.get('_bypass_strategy')}): {waf_tag}",
                            )
                            bypass_plans = self._selector.select_for_spec(bypass_spec, hyp, model, corpus)
                            for bp in bypass_plans:
                                plan_queue.append((bp, depth + 1))
                        if bypass_params_list:
                            log.debug(
                                "experiment.waf_bypass_queued",
                                waf=waf_tag,
                                n_strategies=len(bypass_params_list),
                            )
                    except Exception as exc:
                        log.debug("experiment.waf_bypass_failed", error=str(exc))

            # ── Transport-level WAF bypass (Phase 2) ──────────────────
            # Déclenché sur les mêmes 403/406 que le bypass d'encodage.
            # Applicable à toutes les mutations (pas seulement payload), d'où l'absence
            # de guard "payload in mutation_params".
            # _bypass_attempted empêche la récursion (même flag que le bypass encodage).
            if (
                depth < self._MAX_FOLLOWUP_DEPTH
                and mutation.response_received is not None
                and mutation.response_received.status_code in (403, 406)
                and model is not None
                and not plan.experiment_spec.mutation_params.get("_bypass_attempted")
            ):
                waf_tags = [t for t in model.tech_stack if t.startswith("waf:")]
                if waf_tags:
                    try:
                        from hdwp.core.payloads.waf_bypass.bypass_registry import get_bypass_registry
                        from hdwp.core.model.schemas import ExperimentSpec
                        bypass_registry = get_bypass_registry()
                        cat = "evasion" if depth == 0 else None
                        strategies = bypass_registry.get_strategies_for_waf(
                            waf_tags[0], max_count=2, category=cat
                        )
                        for strategy in strategies:
                            transport_spec = ExperimentSpec(
                                mutation_type=plan.experiment_spec.mutation_type,
                                base_request=plan.experiment_spec.base_request,
                                mutation_params={
                                    **dict(plan.experiment_spec.mutation_params),
                                    "_transport_bypass": strategy.name,
                                    "_bypass_attempted": True,
                                },
                                description=(
                                    f"Transport bypass [{strategy.name}] for {waf_tags[0]}"
                                ),
                            )
                            transport_plans = self._selector.select_for_spec(
                                transport_spec, hyp, model, corpus
                            )
                            for tp in transport_plans:
                                plan_queue.append((tp, depth + 1))
                        if strategies:
                            log.debug(
                                "experiment.transport_bypass_queued",
                                waf=waf_tags[0],
                                n_strategies=len(strategies),
                            )
                    except Exception as exc:
                        log.debug("experiment.transport_bypass_error", error=str(exc))

            # ── replay (reproducibility) ──────────────────────────────
            replay = await self._execute(
                mutated_req, hyp.id, plan.experiment_spec,
                replayed_from=mutation.id, role=mutation_role,
            )
            experiment_ids.append(replay.id)
            self._results_buffer[hyp.id].append(replay)
            await self._bus.emit(EXPERIMENT_RESULT, replay.model_dump(), source="experiment_engine")

        if baseline_id and experiment_ids:
            # Drain avant d'émettre experiments_ready : garantit que tous les
            # handlers experiment.result sont complétés avant que l'oracle évalue.
            await self._bus.drain()
            await self._bus.emit(
                HYPOTHESIS_EXPERIMENTS_READY,
                {
                    "hypothesis_id": hyp.id,
                    "baseline_id": baseline_id,
                    "experiment_ids": experiment_ids,
                },
                source="experiment_engine",
            )
        else:
            log.warning("experiment.all_baselines_invalid", hypothesis_id=hyp.id)
            await self._bus.emit(
                HYPOTHESIS_STATUS_CHANGED,
                {"id": hyp.id, "old_status": hyp.status.value, "new_status": "INSUFFICIENT_DATA"},
                source="experiment_engine",
            )
        self._results_buffer.pop(hyp.id, None)

    async def _execute(
        self,
        req: NormalizedRequest,
        hypothesis_id: str,
        spec: ExperimentSpec,
        replayed_from: str | None = None,
        role: str = "anonymous",
    ) -> ExperimentResult:
        await self._rate_limiter.acquire()
        client = self._session_manager.get_client(role)

        # Injecter les vrais credentials du rôle par-dessus les headers redactés.
        # Pour OAuth2 : acquiert le token si nécessaire (async).
        auth_headers = await self._session_manager.resolve_auth_headers(role)
        effective_req = req.model_copy(
            update={"headers": {**req.headers, **auth_headers}}
        ) if auth_headers else req

        timing_ms: float = 0.0
        norm_resp = normalize_response(0, {}, None, 0.0)
        start = time.monotonic()
        try:
            http_resp = await _send(client, effective_req)
            timing_ms = (time.monotonic() - start) * 1000
            self._session_manager.update_csrf(http_resp, role)
            norm_resp = normalize_response(
                status_code=http_resp.status_code,
                headers=dict(http_resp.headers),
                body=http_resp.text,
                timing_ms=timing_ms,
            )
            # Refresh automatique OAuth2 sur 401 (via resolve_auth_headers async)
            if http_resp.status_code == 401:
                try:
                    new_auth = await self._session_manager.resolve_auth_headers(role)
                    if new_auth:
                        effective_req = effective_req.model_copy(
                            update={"headers": {**effective_req.headers, **new_auth}}
                        )
                        http_resp = await _send(client, effective_req)
                        timing_ms = (time.monotonic() - start) * 1000
                        norm_resp = normalize_response(
                            http_resp.status_code, dict(http_resp.headers),
                            http_resp.text, timing_ms,
                        )
                        log.info("oauth2.token_refreshed_after_401", role=role)
                except Exception:  # noqa: BLE001, S110
                    pass  # garder la réponse 401 originale
        except Exception as exc:  # noqa: BLE001
            timing_ms = (time.monotonic() - start) * 1000
            log.warning("experiment.request_failed", url=req.url, error=str(exc))
            norm_resp = normalize_response(0, {}, None, timing_ms)

        return ExperimentResult(
            hypothesis_id=hypothesis_id,
            experiment_spec=spec,
            request_sent=req,
            response_received=norm_resp,
            timing_ms=timing_ms,
            replayed_from=replayed_from,
            timestamp=datetime.now(UTC).isoformat(),
        )

    async def execute_single(
        self,
        request: NormalizedRequest,
        role_name: str = "anonymous",
        chain_type: str = "chain",
    ) -> ExperimentResult:
        """Exécute une seule requête HTTP avec auth. Utilisé par le ChainEngine."""
        from hdwp.core.model.schemas import ExperimentSpec
        placeholder_spec = ExperimentSpec(
            mutation_type=chain_type,
            base_request=request,
            mutation_params={"chain_type": chain_type},
            description=f"Chain step [{chain_type}]",
        )
        result = await self._execute(
            request,
            hypothesis_id=f"chain-{chain_type}",
            spec=placeholder_spec,
            replayed_from=None,
            role=role_name,
        )
        from hdwp.core.bus.events import EXPERIMENT_RESULT
        # Passer result.model_dump() directement — le bus encapsule lui-même dans HDWPEvent.
        # Passer un HDWPEvent comme payload crée une double-encapsulation qui casse les subscribers.
        await self._bus.emit(EXPERIMENT_RESULT, result.model_dump(), source="chain_engine")
        return result

    def get_results(self, hypothesis_id: str) -> list[ExperimentResult]:
        return self._results_buffer.get(hypothesis_id, [])


# ── helpers ───────────────────────────────────────────────────────────────


async def _send(client: httpx.AsyncClient, req: NormalizedRequest) -> httpx.Response:
    """Build and send an httpx request from a NormalizedRequest."""
    headers: dict[str, Any] = {
        k: v for k, v in req.headers.items() if v != "[REDACTED]"
    }
    # Phase 2: raw body override for smuggling/chunked strategies
    if req.raw_body_override is not None:
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            content=req.raw_body_override,
        )
    if isinstance(req.body, dict):
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            json=req.body,
        )
    if isinstance(req.body, str):
        return await client.request(
            method=req.method,
            url=req.url,
            headers=headers,
            content=req.body.encode(),
        )
    return await client.request(
        method=req.method,
        url=req.url,
        headers=headers,
    )
