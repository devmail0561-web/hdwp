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

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    EXPERIMENT_RESULT,
    HYPOTHESIS_EXPERIMENTS_READY,
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

    async def run_pending(self, hypotheses: list[Hypothesis]) -> None:
        """Execute all hypotheses in priority order (HIGH → LOW)."""
        for hyp in hypotheses:
            await self._run_hypothesis(hyp)

    async def _run_hypothesis(self, hyp: Hypothesis) -> None:
        model = self._model_accessor()
        if model is None:
            log.warning("experiment.no_model", hypothesis_id=hyp.id)
            return

        corpus = self._corpus_accessor()
        plans = self._selector.select_for_hypothesis(hyp, model, corpus)
        if not plans:
            log.warning("experiment.no_plans", hypothesis_id=hyp.id)
            return

        baseline_id: str | None = None
        experiment_ids: list[str] = []
        self._results_buffer[hyp.id] = []

        for plan in plans:
            # Rôle effectif pour les requêtes mutées selon le type de mutation
            mutation_role = (
                plan.target_role
                if plan.mutation_type in ("identity_swap", "privilege_escalation") and plan.target_role
                else plan.baseline_role
            )

            # ── baseline (legitimate access) ──────────────────────────
            baseline = await self._execute(
                plan.baseline_request, hyp.id, plan.experiment_spec,
                role=plan.baseline_role,
            )
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

    def get_results(self, hypothesis_id: str) -> list[ExperimentResult]:
        return self._results_buffer.get(hypothesis_id, [])


# ── helpers ───────────────────────────────────────────────────────────────


async def _send(client: httpx.AsyncClient, req: NormalizedRequest) -> httpx.Response:
    """Build and send an httpx request from a NormalizedRequest."""
    headers: dict[str, Any] = {
        k: v for k, v in req.headers.items() if v != "[REDACTED]"
    }
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
