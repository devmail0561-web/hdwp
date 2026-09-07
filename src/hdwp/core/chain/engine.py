# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""ChainEngine : corrèle les findings confirmés et génère des chaînes d'attaque."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable

import structlog

from hdwp.core.bus.events import FINDING_CONFIRMED, FINDINGS_CORRELATED
from hdwp.core.chain.rules import (
    rule_active_pivot,
    rule_bola_escalation,
    rule_cors_xss,
    rule_generic_active_chain,
    rule_jwt_privesc,
    rule_precondition_chain,
    rule_sqli_exfil,
)
from hdwp.core.chain.utils import extract_value, inject_context
from hdwp.core.model.schemas import ChainSpec, Finding, generate_id

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.store.repository import Repository

log = structlog.get_logger()


class ChainEngine:
    """Génère et exécute des chaînes d'attaque quand 2+ findings confirment des vulnérabilités corrélées."""

    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable,
        flow_map_accessor: Callable,
        repository: Repository,
        target_url: str = "",
        roles: list | None = None,
        session_id: str = "",
    ) -> None:
        self._bus = bus
        self._model_accessor = model_accessor
        self._flow_map_accessor = flow_map_accessor
        self._repository = repository
        self._target_url = target_url
        self._session_id = session_id
        self._roles = roles or []
        self._confirmed_findings: list[Finding] = []
        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)

    async def _on_finding_confirmed(self, event: Any) -> None:
        try:
            finding = Finding.model_validate(event.payload)
            self._confirmed_findings.append(finding)
        except Exception:
            log.warning("chain.finding_parse_error", exc_info=True)

    def has_pending_chains(self) -> bool:
        return len(self._confirmed_findings) >= 2

    async def run_for_findings(
        self, finding_ids: list[str], exp_engine: Any
    ) -> list[dict]:
        """Exécute les chaînes à la demande pour un sous-ensemble de findings.

        Utilisé depuis les routes API — bypasse self._confirmed_findings (qui peut
        être vide sur une session reprise) et charge les findings directement depuis le repo.
        """
        findings = []
        for fid in finding_ids:
            f = await self._repository.get_finding(fid)
            if f:
                findings.append(f)
        if len(findings) < 1:
            return []

        model = self._model_accessor()
        flow_map = self._flow_map_accessor()

        all_specs: list[ChainSpec] = []
        # Règles spécifiques en premier (priorité haute)
        all_specs += rule_bola_escalation(findings, model, self._target_url)
        all_specs += rule_sqli_exfil(findings, model, flow_map, self._target_url)
        all_specs += rule_jwt_privesc(findings, model, self._target_url)
        all_specs += rule_cors_xss(findings, model, flow_map, self._target_url)
        # Fallback générique (garantit des chaînes exécutables)
        all_specs += rule_generic_active_chain(findings, model, self._target_url)
        # Pivot et théoriques en dernier (priorité basse)
        all_specs += rule_active_pivot(findings, model, self._target_url)
        all_specs += rule_precondition_chain(findings, model, self._target_url)

        # Dédupliquer par ensemble de finding IDs (règles spécifiques prioritaires)
        seen_ids: set[frozenset] = set()
        deduped_specs: list[ChainSpec] = []
        for spec in all_specs:
            key = frozenset(spec.precondition_finding_ids)
            if key not in seen_ids:
                seen_ids.add(key)
                deduped_specs.append(spec)
        all_specs = deduped_specs

        results = []
        for spec in all_specs:
            log.info("chain.on_demand", chain_type=spec.chain_type, executable=spec.executable)

            # Chaîne théorique : retourner sans exécution HTTP
            if not spec.executable:
                results.append({
                    "chain_type": spec.chain_type,
                    "description": spec.description,
                    "success": None,
                    "status": "theoretical",
                    "steps": [],
                    "context_values": {},
                    "trigger_finding_ids": spec.precondition_finding_ids,
                    "missing_preconditions": spec.missing_preconditions,
                    "executable": False,
                })
                continue

            success, proof = await self._execute_chain(spec, exp_engine)
            result = {
                "chain_type": spec.chain_type,
                "description": spec.description,
                "success": success,
                "trigger_finding_ids": spec.precondition_finding_ids,
                **proof,
            }
            results.append(result)
            if success:
                await self._save_chain_finding(spec, proof)
                await self._bus.emit(FINDINGS_CORRELATED, {
                    "chain_type": spec.chain_type,
                    "description": spec.description,
                    "status": "success",
                }, source="chain_engine")
        return results

    async def discover_chains(self, finding_ids: list[str] | None = None) -> list[dict]:
        """Évalue les règles de corrélation sans exécuter les chaînes.

        Retourne les specs candidates pour affichage dans le sous-onglet Chaînes.
        """
        if finding_ids is not None:
            findings = []
            for fid in finding_ids:
                f = await self._repository.get_finding(fid)
                if f:
                    findings.append(f)
        else:
            findings = await self._repository.list_findings(status="CONFIRMED")

        if len(findings) < 2:
            return []

        model = self._model_accessor()
        flow_map = self._flow_map_accessor()

        all_specs: list[ChainSpec] = []
        # Règles spécifiques en premier (priorité haute)
        all_specs += rule_bola_escalation(findings, model, self._target_url)
        all_specs += rule_sqli_exfil(findings, model, flow_map, self._target_url)
        all_specs += rule_jwt_privesc(findings, model, self._target_url)
        all_specs += rule_cors_xss(findings, model, flow_map, self._target_url)
        # Fallback générique (garantit des chaînes exécutables)
        all_specs += rule_generic_active_chain(findings, model, self._target_url)
        # Pivot et théoriques en dernier (priorité basse)
        all_specs += rule_active_pivot(findings, model, self._target_url)
        all_specs += rule_precondition_chain(findings, model, self._target_url)

        seen_ids: set[frozenset] = set()
        deduped: list[ChainSpec] = []
        for spec in all_specs:
            key = frozenset(spec.precondition_finding_ids)
            if key not in seen_ids:
                seen_ids.add(key)
                deduped.append(spec)

        return [
            {
                "chain_type": spec.chain_type,
                "description": spec.description,
                "precondition_finding_ids": spec.precondition_finding_ids,
                "executable": spec.executable,
                "missing_preconditions": spec.missing_preconditions,
            }
            for spec in deduped
        ]

    async def run_pending_chains(self, exp_engine: Any) -> list[ChainSpec]:
        """Évalue les règles et exécute les chaînes générées."""
        if not self._confirmed_findings:
            return []

        model = self._model_accessor()
        flow_map = self._flow_map_accessor()
        findings = self._confirmed_findings

        all_specs: list[ChainSpec] = []
        # Règles spécifiques en premier (priorité haute)
        all_specs += rule_bola_escalation(findings, model, self._target_url)
        all_specs += rule_sqli_exfil(findings, model, flow_map, self._target_url)
        all_specs += rule_jwt_privesc(findings, model, self._target_url)
        all_specs += rule_cors_xss(findings, model, flow_map, self._target_url)
        # Fallback générique (garantit des chaînes exécutables)
        all_specs += rule_generic_active_chain(findings, model, self._target_url)
        # Pivot et théoriques en dernier (priorité basse)
        all_specs += rule_active_pivot(findings, model, self._target_url)
        all_specs += rule_precondition_chain(findings, model, self._target_url)

        # Dédupliquer par ensemble de finding IDs
        seen_ids: set[frozenset] = set()
        deduped_specs: list[ChainSpec] = []
        for spec in all_specs:
            key = frozenset(spec.precondition_finding_ids)
            if key not in seen_ids:
                seen_ids.add(key)
                deduped_specs.append(spec)
        all_specs = deduped_specs

        executed = []
        for spec in all_specs:
            if not spec.executable:
                continue  # Chaînes théoriques : pas d'exécution HTTP au scan time
            log.info("chain.executing", chain_type=spec.chain_type, steps=len(spec.steps))
            success, proof = await self._execute_chain(spec, exp_engine)
            if success:
                await self._save_chain_finding(spec, proof)
                await self._bus.emit(FINDINGS_CORRELATED, {
                    "chain_type": spec.chain_type,
                    "description": spec.description,
                    "trigger_finding_ids": spec.precondition_finding_ids,
                    "status": "success",
                }, source="chain_engine")
                executed.append(spec)
                log.info("chain.success", chain_type=spec.chain_type)
            else:
                log.info("chain.failed", chain_type=spec.chain_type)

        return executed

    async def _execute_direct(
        self, request: Any, role_name: str
    ) -> Any:
        """Exécute une requête HTTP via httpx direct (sans ExperimentEngine).

        Fallback utilisé quand le moteur n'est plus en mémoire (session reprise).
        """
        import time
        import httpx
        from hdwp.core.model.schemas import ExperimentResult, ExperimentSpec, generate_id
        from hdwp.core.observation.normalizer import normalize_response

        import base64
        auth_headers: dict = {}
        if role_name != "anonymous":
            for role in self._roles:
                if getattr(role, "name", None) != role_name:
                    continue
                cred = getattr(role, "credentials", None)
                if not cred:
                    continue
                ctype = getattr(cred, "type", "")
                if ctype == "bearer" and getattr(cred, "token", None):
                    auth_headers["Authorization"] = f"Bearer {cred.token}"
                    break
                elif ctype == "basic" and getattr(cred, "username", None):
                    enc = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
                    auth_headers["Authorization"] = f"Basic {enc}"
                    break
                elif ctype == "cookie" and getattr(cred, "token", None):
                    auth_headers["Cookie"] = cred.token
                    break

        all_headers = {**dict(request.headers or {}), **auth_headers,
                       "User-Agent": "HDWP-Chain/0.1"}
        params = dict(request.query_params) if request.query_params else None
        body = request.body

        start = time.monotonic()
        try:
            from hdwp.core.http_client import build_client
            async with build_client() as client:
                r = await client.request(
                    method=request.method,
                    url=request.url,
                    params=params,
                    json=body if isinstance(body, dict) else None,
                    content=body.encode() if isinstance(body, str) else None,
                    headers=all_headers,
                )
        except Exception as exc:
            raise RuntimeError(f"HTTP error: {exc}") from exc

        elapsed = (time.monotonic() - start) * 1000
        norm_resp = normalize_response(r.status_code, dict(r.headers), r.text, elapsed)

        placeholder_spec = ExperimentSpec(
            mutation_type="chain_direct", base_request=request,
            mutation_params={}, description="Direct chain step",
        )
        return ExperimentResult(
            id=generate_id("EXP"),
            hypothesis_id="chain-direct",
            experiment_spec=placeholder_spec,
            request_sent=request,
            response_received=norm_resp,
            timing_ms=elapsed,
            replayed_from=None,
        )

    async def _execute_chain(
        self, spec: ChainSpec, exp_engine: Any
    ) -> tuple[bool, dict]:
        context: dict[str, Any] = {}
        step_results = []

        for step in spec.steps:
            request = inject_context(step.request, context, step.inject_context)
            try:
                if exp_engine is not None:
                    result = await exp_engine.execute_single(
                        request, step.role_name, chain_type=spec.chain_type
                    )
                else:
                    result = await self._execute_direct(request, step.role_name)
            except Exception as exc:
                log.warning("chain.step_failed", step=step.step_index, error=str(exc))
                return False, {}

            step_results.append({
                "step": step.step_index,
                "status_code": result.response_received.status_code,
                "url": result.request_sent.url,
            })

            body = result.response_received.body
            for var_name, path in step.context_extractors.items():
                context[var_name] = extract_value(body, path)

        terminal = step_results[-1] if step_results else {}
        # 3xx redirections ≠ exploitation réussie : seuls les 2xx confirment l'accès effectif
        success = 200 <= terminal.get("status_code", 500) < 300

        proof = {
            "chain_type": spec.chain_type,
            "steps": step_results,
            "context_values": {k: str(v)[:200] for k, v in context.items()},
            "description": spec.description,
        }
        return success, proof

    async def _save_chain_finding(self, spec: ChainSpec, proof: dict) -> None:
        try:
            await self._repository.save_chain_finding(
                chain_id=generate_id("CHN"),
                session_id=self._session_id,
                chain_type=spec.chain_type,
                trigger_finding_ids=spec.precondition_finding_ids,
                severity="HIGH",
                confidence=0.8,
                proof=proof,
            )
        except Exception as exc:
            log.warning("chain.save_failed", error=str(exc))
