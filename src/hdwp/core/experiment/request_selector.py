# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
RequestSelector: bridges the gap between abstract ExperimentSpec and concrete HTTP requests.

Given a Hypothesis and the ApplicationModel's request corpus, produces
ConcreteExperimentPlan objects the ExperimentEngine can execute directly.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
)


@dataclass
class ConcreteExperimentPlan:
    """A fully resolved experiment ready for execution by the ExperimentEngine."""

    hypothesis_id: str
    mutation_type: str
    baseline_request: NormalizedRequest
    baseline_role: str
    target_role: str | None
    mutated_value: str | None
    mutated_param_name: str | None
    mutated_param_location: str | None
    description: str
    experiment_spec: ExperimentSpec


class RequestSelector:
    """
    Resolves abstract ExperimentSpec objects into ConcreteExperimentPlan objects
    by matching them against the ApplicationModel's observed request corpus.
    """

    def select_for_hypothesis(
        self,
        hyp: Hypothesis,
        model_snapshot: ApplicationModelData,
        request_corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """Return concrete experiment plans for all ExperimentSpecs in the hypothesis."""
        plans: list[ConcreteExperimentPlan] = []
        for spec in hyp.required_experiments:
            match spec.mutation_type:
                case "identity_swap":
                    plans.extend(self._plan_identity_swap(hyp, spec, model_snapshot, request_corpus))
                case "object_ref_change":
                    plans.extend(self._plan_object_ref_change(hyp, spec, model_snapshot, request_corpus))
                case "privilege_escalation":
                    plans.extend(self._plan_privilege_escalation(hyp, spec, model_snapshot, request_corpus))
                case "field_injection":
                    plans.extend(self._plan_field_injection(hyp, spec, model_snapshot, request_corpus))
                case "jwt_manipulation":
                    plans.extend(self._plan_jwt_manipulation(hyp, spec, model_snapshot, request_corpus))
                case "origin_test":
                    plans.extend(self._plan_origin_test(hyp, spec, model_snapshot, request_corpus))
        return plans

    # ── identity_swap ──────────────────────────────────────────────────────────

    def _plan_identity_swap(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """
        For each path_pattern where ≥2 non-anonymous roles have observed requests,
        produce one plan: replay role_a's request with role_b's identity.
        """
        plans: list[ConcreteExperimentPlan] = []
        named_roles = [r.name for r in model.roles if r.name != "anonymous"]
        if len(named_roles) < 2:
            return plans

        for requests in corpus.values():
            by_role: dict[str, list[NormalizedRequest]] = {}
            for role_name, req in requests:
                by_role.setdefault(role_name, []).append(req)

            present = [r for r in named_roles if r in by_role]
            if len(present) < 2:
                continue

            role_a, role_b = present[0], present[1]
            baseline = by_role[role_a][0]
            plans.append(ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="identity_swap",
                baseline_request=baseline,
                baseline_role=role_a,
                target_role=role_b,
                mutated_value=None,
                mutated_param_name=None,
                mutated_param_location=None,
                description=(
                    f"Replay {baseline.method} {baseline.url} "
                    f"replacing '{role_a}' credentials with '{role_b}'"
                ),
                experiment_spec=spec,
            ))

        return plans

    # ── object_ref_change ──────────────────────────────────────────────────────

    def _plan_object_ref_change(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """
        For each role pair, try to access an object ID owned by the other role.
        Falls back to a sequential +1 probe when only one role is present.
        """
        plans: list[ConcreteExperimentPlan] = []
        param_name = spec.mutation_params.get("parameter_name", "")
        param_location = spec.mutation_params.get("parameter_location", "path")

        # Collect observed parameter values per role
        values_by_role: dict[str, list[str]] = {}
        for path_pattern, requests in corpus.items():
            for role_name, req in requests:
                val = self._extract_param_value(req, param_name, param_location, path_pattern)
                if val is not None:
                    bucket = values_by_role.setdefault(role_name, [])
                    if val not in bucket:
                        bucket.append(val)
                    if len(bucket) > 5:
                        bucket[:] = bucket[:5]

        roles = list(values_by_role)
        if not roles:
            return plans

        # Cross-role: role_a tries role_b's object
        for role_a in roles:
            for role_b in roles:
                if role_b == role_a:
                    continue
                vals_a = values_by_role[role_a]
                vals_b = values_by_role[role_b]
                if not vals_a or not vals_b:
                    continue
                target_val = vals_b[0]
                if target_val == vals_a[0]:
                    continue
                baseline = self._find_request_with_param(
                    corpus, role_a, param_name, param_location, vals_a[0]
                )
                if baseline is None:
                    continue
                plans.append(ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="object_ref_change",
                    baseline_request=baseline,
                    baseline_role=role_a,
                    target_role=None,
                    mutated_value=target_val,
                    mutated_param_name=param_name,
                    mutated_param_location=param_location,
                    description=(
                        f"Access {param_name}={target_val} "
                        f"(owned by '{role_b}') using '{role_a}' credentials"
                    ),
                    experiment_spec=spec,
                ))

        # Fallback: multi-probe strategy when only one role observed
        if not plans and len(roles) == 1:
            role = roles[0]
            vals = values_by_role[role]
            if vals:
                baseline = self._find_request_with_param(
                    corpus, role, param_name, param_location, vals[0]
                )
                if baseline is not None:
                    for probe_val in self._fallback_probe_values(vals[0]):
                        plans.append(ConcreteExperimentPlan(
                            hypothesis_id=hyp.id,
                            mutation_type="object_ref_change",
                            baseline_request=baseline,
                            baseline_role=role,
                            target_role=None,
                            mutated_value=probe_val,
                            mutated_param_name=param_name,
                            mutated_param_location=param_location,
                            description=(
                                f"Probe {param_name}={probe_val} "
                                f"(inférence depuis {vals[0]})"
                            ),
                            experiment_spec=spec,
                        ))

        return plans

    # ── privilege_escalation ───────────────────────────────────────────────────

    def _plan_privilege_escalation(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """
        Find an observed request for the restricted endpoint and plan access
        with the lower-privilege target_role.
        """
        plans: list[ConcreteExperimentPlan] = []
        endpoint_path = spec.mutation_params.get("endpoint_path", "")
        target_role = spec.mutation_params.get("target_role", "")
        if not endpoint_path or not target_role:
            return plans

        prefix = endpoint_path.split("{")[0]
        for path_pattern, requests in corpus.items():
            if path_pattern != endpoint_path and not path_pattern.startswith(prefix):
                continue
            if not requests:
                continue
            obs_role, baseline = requests[0]
            method = spec.base_request.method or "GET"
            plans.append(ConcreteExperimentPlan(
                hypothesis_id=hyp.id,
                mutation_type="privilege_escalation",
                baseline_request=NormalizedRequest(
                    method=method,
                    url=baseline.url,
                    headers=dict(baseline.headers),
                    body=baseline.body,
                    query_params=dict(baseline.query_params),
                    path_params=dict(baseline.path_params),
                ),
                baseline_role=obs_role,
                target_role=target_role,
                mutated_value=None,
                mutated_param_name=None,
                mutated_param_location=None,
                description=f"Access '{endpoint_path}' with unauthorized role '{target_role}'",
                experiment_spec=spec,
            ))
            break  # one plan per endpoint is sufficient

        return plans

    # ── helpers ────────────────────────────────────────────────────────────────

    def _extract_param_value(
        self,
        req: NormalizedRequest,
        param_name: str,
        location: str,
        path_pattern: str,
    ) -> str | None:
        if location == "query":
            return req.query_params.get(param_name)
        if location == "body" and isinstance(req.body, dict):
            v = req.body.get(param_name)
            return str(v) if v is not None else None
        if location == "path":
            return self._extract_path_value(req.url, path_pattern, param_name)
        return None

    @staticmethod
    def _extract_path_value(url: str, path_pattern: str, param_name: str) -> str | None:
        """
        Match concrete URL segments against path pattern placeholders
        and return the value for the requested parameter slot.
        """
        url_parts = urlparse(url).path.strip("/").split("/")
        pat_parts = path_pattern.strip("/").split("/")
        if len(url_parts) != len(pat_parts):
            return None
        for url_seg, pat_seg in zip(url_parts, pat_parts):
            if pat_seg.startswith("{") and pat_seg.endswith("}"):
                slot = pat_seg[1:-1]  # e.g. "id_0"
                if param_name in slot or slot in param_name or param_name.startswith("path_"):
                    return url_seg
        return None

    def _fallback_probe_values(self, current_value: str) -> list[str]:
        """
        Génère plusieurs valeurs candidates quand un seul rôle est observé.
        Couvre : integers séquentiels + petits IDs + UUIDs aléatoires.
        """
        probes: list[str] = []

        # Integers : N-1, 1, 2, 3, N+1 (sans inclure N ni les négatifs)
        try:
            n = int(current_value)
            candidates: set[int] = {n - 1, n + 1, 1, 2, 3}
            candidates.discard(n)
            candidates.discard(0)
            candidates.discard(-1)
            probes.extend(str(c) for c in sorted(candidates) if c > 0)
        except ValueError:
            pass

        # UUIDs : générer 2 UUID v4 aléatoires
        _uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        if _uuid_re.match(current_value):
            probes.append(str(uuid.uuid4()))
            probes.append(str(uuid.uuid4()))

        return probes[:3]  # max 3 probes pour limiter le flood

    @staticmethod
    def _find_request_with_param(
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
        role_name: str,
        param_name: str,
        location: str,
        value: str,
    ) -> NormalizedRequest | None:
        for requests in corpus.values():
            for r_name, req in requests:
                if r_name != role_name:
                    continue
                if location == "query" and req.query_params.get(param_name) == value:
                    return req
                if location == "body" and isinstance(req.body, dict) and str(req.body.get(param_name, "")) == value:
                    return req
                if location == "path" and value in req.url:
                    return req
        return None

    def _plan_field_injection(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """
        Pour field_injection : trouver une requête observée qui utilise le paramètre
        cible, puis planifier l'injection du payload dedans.

        Fallback : si aucune requête n'a ce paramètre, utiliser la première requête
        disponible dans le corpus (permet de tester même sans observation préalable).
        """
        param_name = spec.mutation_params.get("parameter_name", "")
        param_location = spec.mutation_params.get("parameter_location", "query")
        payload = spec.mutation_params.get("payload", "")
        payload_type = spec.mutation_params.get("payload_type", "sqli")

        if not payload:
            return []

        # Chercher une requête qui a ce paramètre
        for path, requests in corpus.items():
            for role_name, req in requests:
                value = self._extract_param_value(req, param_name, param_location, path)
                if value is not None:
                    return [ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="field_injection",
                        baseline_request=req,
                        baseline_role=role_name,
                        target_role=None,
                        mutated_value=payload,
                        mutated_param_name=param_name,
                        mutated_param_location=param_location,
                        description=(
                            f"Inject {payload_type.upper()} into '{param_name}': {payload[:30]}"
                        ),
                        experiment_spec=spec,
                    )]

        # Fallback : première requête disponible dans le corpus
        for requests in corpus.values():
            if requests:
                role_name, req = requests[0]
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="field_injection",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=payload,
                    mutated_param_name=param_name,
                    mutated_param_location=param_location,
                    description=(
                        f"Inject {payload_type.upper()} (fallback): {payload[:30]}"
                    ),
                    experiment_spec=spec,
                )]

        return []

    def _plan_jwt_manipulation(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """JWT manipulation: use any authenticated endpoint as baseline."""
        target_path = spec.mutation_params.get("target_endpoint", "")

        # Prefer the target endpoint, fall back to any authenticated request
        for path, requests in corpus.items():
            if not requests:
                continue
            if not target_path or path == target_path or path.startswith(target_path.split("{")[0]):
                role_name, req = requests[0]
                if role_name != "anonymous":
                    return [ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="jwt_manipulation",
                        baseline_request=req,
                        baseline_role=role_name,
                        target_role=None,
                        mutated_value=None,
                        mutated_param_name=None,
                        mutated_param_location=None,
                        description=spec.description,
                        experiment_spec=spec,
                    )]

        # Fallback: any non-anonymous request
        for requests in corpus.values():
            for role_name, req in requests:
                if role_name != "anonymous":
                    return [ConcreteExperimentPlan(
                        hypothesis_id=hyp.id,
                        mutation_type="jwt_manipulation",
                        baseline_request=req,
                        baseline_role=role_name,
                        target_role=None,
                        mutated_value=None,
                        mutated_param_name=None,
                        mutated_param_location=None,
                        description=spec.description,
                        experiment_spec=spec,
                    )]
        return []

    def _plan_origin_test(
        self,
        hyp: Hypothesis,
        spec: ExperimentSpec,
        model: ApplicationModelData,
        corpus: dict[str, list[tuple[str, NormalizedRequest]]],
    ) -> list[ConcreteExperimentPlan]:
        """CORS origin test: any endpoint request works as baseline."""
        endpoint_path = spec.mutation_params.get("endpoint_path", "")
        evil_origin = spec.mutation_params.get("evil_origin", "https://evil.hdwp-test.invalid")

        for path, requests in corpus.items():
            if not requests:
                continue
            if not endpoint_path or path == endpoint_path or path.startswith(endpoint_path.split("{")[0]):
                role_name, req = requests[0]
                return [ConcreteExperimentPlan(
                    hypothesis_id=hyp.id,
                    mutation_type="origin_test",
                    baseline_request=req,
                    baseline_role=role_name,
                    target_role=None,
                    mutated_value=evil_origin,
                    mutated_param_name=None,
                    mutated_param_location=None,
                    description=f"CORS test: Origin: {evil_origin}",
                    experiment_spec=spec,
                )]
        return []
