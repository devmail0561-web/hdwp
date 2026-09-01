# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
TemporalModule: exécute les expériences nécessitant concurrence ou timing.

Types :
- race_condition : N requêtes simultanées (détecte incohérences d'état)
- token_reuse   : vérifie qu'un token invalidé post-logout ne fonctionne plus
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from hdwp.core.model.schemas import ExperimentResult, ExperimentSpec, NormalizedRequest
from hdwp.core.observation.normalizer import normalize_response

log = structlog.get_logger()


class TemporalModule:
    """Exécute des expériences temporelles (concurrence, timing, rejeu)."""

    async def run_race_condition(
        self,
        client: httpx.AsyncClient,
        request: NormalizedRequest,
        hypothesis_id: str,
        spec: ExperimentSpec,
        concurrency: int = 10,
    ) -> list[ExperimentResult]:
        """Envoie N requêtes simultanées et collecte tous les résultats."""

        async def _single(_i: int) -> ExperimentResult:
            start = time.monotonic()
            try:
                resp = await client.request(
                    method=request.method,
                    url=request.url,
                    headers={k: v for k, v in request.headers.items() if v != "[REDACTED]"},
                    json=request.body if isinstance(request.body, dict) else None,
                )
                timing = (time.monotonic() - start) * 1000
                norm_resp = normalize_response(
                    resp.status_code, dict(resp.headers), resp.text, timing
                )
            except httpx.HTTPError as exc:
                timing = (time.monotonic() - start) * 1000
                log.warning("temporal.request_failed", error=str(exc))
                norm_resp = normalize_response(0, {}, None, timing)
            return ExperimentResult(
                hypothesis_id=hypothesis_id,
                experiment_spec=spec,
                request_sent=request,
                response_received=norm_resp,
                timing_ms=timing,
                timestamp=datetime.now(UTC).isoformat(),
            )

        results = await asyncio.gather(*[_single(i) for i in range(concurrency)])
        return list(results)

    async def run_token_reuse(
        self,
        client: httpx.AsyncClient,
        original_request: NormalizedRequest,
        logout_request: NormalizedRequest | None,
        hypothesis_id: str,
        spec: ExperimentSpec,
    ) -> list[ExperimentResult]:
        """
        1. Envoie la requête originale → baseline
        2. Simule un logout (si fourni)
        3. Rejoue la requête originale → doit retourner 401 si invalidation ok
        """
        results: list[ExperimentResult] = []

        async def _send(req: NormalizedRequest, replayed_from: str | None = None) -> ExperimentResult:
            start = time.monotonic()
            try:
                resp = await client.request(
                    method=req.method,
                    url=req.url,
                    headers={k: v for k, v in req.headers.items() if v != "[REDACTED]"},
                )
                timing = (time.monotonic() - start) * 1000
                norm_resp = normalize_response(
                    resp.status_code, dict(resp.headers), resp.text, timing
                )
            except httpx.HTTPError:
                norm_resp = normalize_response(0, {}, None, 0.0)
            return ExperimentResult(
                hypothesis_id=hypothesis_id,
                experiment_spec=spec,
                request_sent=req,
                response_received=norm_resp,
                timing_ms=(time.monotonic() - start) * 1000,
                replayed_from=replayed_from,
                timestamp=datetime.now(UTC).isoformat(),
            )

        baseline = await _send(original_request)
        results.append(baseline)

        if logout_request:
            try:
                await client.request(
                    method=logout_request.method,
                    url=logout_request.url,
                    headers={k: v for k, v in logout_request.headers.items() if v != "[REDACTED]"},
                )
            except httpx.HTTPError:
                pass

        replay = await _send(original_request, replayed_from=baseline.id)
        results.append(replay)
        return results

    async def run_race_condition_with_verification(
        self,
        read_client: httpx.AsyncClient,
        write_client: httpx.AsyncClient,
        read_request: NormalizedRequest,
        write_request: NormalizedRequest,
        hypothesis_id: str,
        spec: ExperimentSpec,
        concurrency: int = 10,
    ) -> dict[str, Any]:
        """
        Pattern avant/après pour détecter les race conditions "all succeed".

        ATTENTION : Cette méthode effectue une VRAIE opération d'écriture avant le test
        (write_request×1) pour mesurer delta_per_op. Sur une cible réelle, cela
        décrémente le stock, débite un compte, etc. Requiert allow_write=True.

        Séquence :
        1. Mesurer delta_per_op : GET → WRITE×1 → GET  (1 opération réelle)
        2. Lancer N requêtes concurrentes (N opérations réelles)
        3. GET final → comparer delta_race vs N×delta_per_op
        """
        state_0 = await _read_state(read_client, read_request)
        await _read_state(write_client, write_request)  # 1 écriture baseline
        await asyncio.sleep(0.2)
        state_1 = await _read_state(read_client, read_request)

        before_race = state_1

        race_results = await self.run_race_condition(
            write_client, write_request, hypothesis_id, spec, concurrency
        )
        await asyncio.sleep(0.5)

        after_race = await _read_state(read_client, read_request)

        return _analyze_state_change(
            state_0, state_1, before_race, after_race, race_results, concurrency
        )


async def _read_state(client: httpx.AsyncClient, req: NormalizedRequest) -> ExperimentResult:
    """Exécute une requête et retourne l'ExperimentResult (helper pour verification)."""
    from hdwp.core.model.schemas import ExperimentSpec, generate_id
    start = time.monotonic()
    # Initialiser avant le try pour éviter UnboundLocalError sur exception non-httpx
    timing: float = 0.0
    norm_resp = normalize_response(0, {}, None, 0.0)
    try:
        resp = await client.request(
            method=req.method,
            url=req.url,
            headers={k: v for k, v in req.headers.items() if v != "[REDACTED]"},
            json=req.body if isinstance(req.body, dict) else None,
        )
        timing = (time.monotonic() - start) * 1000
        norm_resp = normalize_response(resp.status_code, dict(resp.headers), resp.text, timing)
    except Exception as exc:  # noqa: BLE001 — httpx.RequestError, CancelledError, SSL, etc.
        timing = (time.monotonic() - start) * 1000
        log.warning("temporal.read_state_failed", error=str(exc))
        norm_resp = normalize_response(0, {}, None, timing)
    return ExperimentResult(
        id=generate_id("EXP"),
        hypothesis_id="_verify",
        experiment_spec=ExperimentSpec(
            mutation_type="_read_state",
            base_request=req,
            mutation_params={},
        ),
        request_sent=req,
        response_received=norm_resp,
        timing_ms=timing,
        timestamp=datetime.now(UTC).isoformat(),
    )


def _analyze_state_change(
    state_0: ExperimentResult,
    state_1: ExperimentResult,
    before_race: ExperimentResult,
    after_race: ExperimentResult,
    race_results: list[ExperimentResult],
    n: int,
) -> dict[str, Any]:
    """
    Détecte les race conditions "all succeed" en comparant delta_per_op vs delta_race.

    delta_per_op   = state_1[field] - state_0[field]   (delta mesuré pour 1 opération)
    expected_delta = delta_per_op × successful
    observed_delta = after_race[field] - before_race[field]

    Si |observed| < |expected| × 0.9 → opérations perdues = race condition.
    """
    b0 = state_0.response_received.body or {}
    b1 = state_1.response_received.body or {}
    b_before = before_race.response_received.body or {}
    b_after  = after_race.response_received.body or {}

    if not all(isinstance(b, dict) for b in [b0, b1, b_before, b_after]):
        return {
            "suspicious": False,
            "confidence": 0.1,
            "rationale": "Bodies non-JSON — analyse avant/après impossible",
        }

    successful = sum(1 for r in race_results if r.response_received.status_code < 300)
    if successful == 0:
        return {
            "suspicious": False,
            "confidence": 0.1,
            "rationale": "Aucune requête race n'a réussi",
        }

    suspicious_fields = []
    common = set(b0) & set(b1) & set(b_before) & set(b_after)

    for field in common:
        v0, v1 = b0[field], b1[field]
        v_br, v_ar = b_before[field], b_after[field]
        if not all(isinstance(v, (int, float)) for v in [v0, v1, v_br, v_ar]):
            continue
        delta_per_op = v1 - v0
        if delta_per_op == 0:
            continue
        expected = delta_per_op * successful
        observed = v_ar - v_br
        if abs(expected) > 0 and abs(observed) < abs(expected) * 0.9:
            lost = round((abs(expected) - abs(observed)) / abs(delta_per_op))
            suspicious_fields.append({
                "field": field,
                "delta_per_op": delta_per_op,
                "observed_delta": observed,
                "expected_delta": expected,
                "lost_ops": lost,
            })

    if suspicious_fields:
        f = suspicious_fields[0]
        return {
            "suspicious": True,
            "confidence": min(0.90, 0.60 + 0.05 * f["lost_ops"]),
            "suspicious_fields": suspicious_fields,
            "rationale": (
                f"Race condition : '{f['field']}' delta={f['observed_delta']:.1f} "
                f"(attendu {f['expected_delta']:.1f}, {f['lost_ops']} op(s) perdues)"
            ),
        }

    return {
        "suspicious": False,
        "confidence": 0.1,
        "rationale": f"Aucune anomalie numérique ({n} requêtes, {successful} succès)",
    }


def assess_race_condition(results: list[ExperimentResult]) -> dict[str, Any]:
    """
    Analyse les résultats d'une race condition.
    Indicateurs suspects : status codes incohérents ou valeurs numériques négatives.
    """
    statuses = [r.response_received.status_code for r in results]
    status_set = set(statuses)

    if len(status_set) > 1:
        return {
            "suspicious": True,
            "rationale": (
                f"Résultats incohérents : statuts {status_set} pour "
                f"{len(results)} requêtes simultanées"
            ),
            "confidence": 0.7,
        }

    for r in results:
        body = r.response_received.body
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, (int, float)) and v < 0:
                    return {
                        "suspicious": True,
                        "rationale": f"Valeur impossible après race condition : {k}={v}",
                        "confidence": 0.85,
                    }

    return {"suspicious": False, "rationale": "Pas d'incohérence détectée", "confidence": 0.6}
