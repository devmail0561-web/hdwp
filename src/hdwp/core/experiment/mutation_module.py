# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MutationModule: transforms a ConcreteExperimentPlan into a mutated NormalizedRequest.

Does NOT execute HTTP — that is the ExperimentEngine's responsibility.
Each mutation type preserves the original request (model_copy) and applies
only the minimal change required to test the hypothesis.
"""
from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, urlunparse

from hdwp.core.experiment.request_selector import ConcreteExperimentPlan
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.model.schemas import NormalizedRequest

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class MutationModule:
    """
    Applies a mutation to a reference request according to the provided plan.
    Returns a new NormalizedRequest ready to be sent.
    """

    def apply(
        self,
        plan: ConcreteExperimentPlan,
        session_manager: SessionManager,
    ) -> NormalizedRequest:
        match plan.mutation_type:
            case "identity_swap":
                return self._apply_identity_swap(plan, session_manager)
            case "object_ref_change":
                return self._apply_object_ref_change(plan)
            case "privilege_escalation":
                return self._apply_privilege_escalation(plan, session_manager)
            case "field_injection":
                return self._apply_field_injection(plan)
            case "jwt_manipulation":
                return self._apply_jwt_manipulation(plan, session_manager)
            case "origin_test":
                return self._apply_origin_test(plan)
            case _:
                return plan.baseline_request

    # ── mutation types ────────────────────────────────────────────────────

    def _apply_identity_swap(
        self, plan: ConcreteExperimentPlan, sm: SessionManager
    ) -> NormalizedRequest:
        """Replace auth headers with target_role credentials."""
        if plan.target_role is None:
            return plan.baseline_request
        new_headers = sm.prepare_headers(plan.target_role, plan.baseline_request.headers)
        return plan.baseline_request.model_copy(update={"headers": new_headers})

    def _apply_object_ref_change(self, plan: ConcreteExperimentPlan) -> NormalizedRequest:
        """Change the value of mutated_param_name in path / query / body."""
        if plan.mutated_value is None or plan.mutated_param_name is None:
            return plan.baseline_request
        req = plan.baseline_request

        match plan.mutated_param_location:
            case "path":
                new_url = _replace_first_id_in_path(req.url, plan.mutated_value)
                return req.model_copy(update={"url": new_url})
            case "query":
                new_params = {**req.query_params, plan.mutated_param_name: plan.mutated_value}
                new_url = _rebuild_url_with_params(req.url, new_params)
                return req.model_copy(update={"url": new_url, "query_params": new_params})
            case "body" if isinstance(req.body, dict):
                new_body = {**req.body, plan.mutated_param_name: plan.mutated_value}
                return req.model_copy(update={"body": new_body})
            case _:
                return req

    def _apply_privilege_escalation(
        self, plan: ConcreteExperimentPlan, sm: SessionManager
    ) -> NormalizedRequest:
        """Access a restricted endpoint with an unauthorised role's credentials."""
        if plan.target_role is None:
            return plan.baseline_request
        new_headers = sm.prepare_headers(plan.target_role, plan.baseline_request.headers)
        return plan.baseline_request.model_copy(update={"headers": new_headers})

    def _apply_field_injection(self, plan: ConcreteExperimentPlan) -> NormalizedRequest:
        """Inject a payload into the target parameter at the specified location."""
        req = plan.baseline_request
        payload = plan.mutated_value or ""
        param = plan.mutated_param_name or ""
        location = plan.mutated_param_location or "query"

        match location:
            case "query":
                new_params = {**req.query_params, param: payload}
                new_url = _rebuild_url_with_params(req.url, new_params)
                return req.model_copy(update={"url": new_url, "query_params": new_params})
            case "body" if isinstance(req.body, dict):
                new_body = {**req.body, param: payload}
                return req.model_copy(update={"body": new_body})
            case "path":
                new_url = _replace_first_id_in_path(req.url, payload)
                return req.model_copy(update={"url": new_url})
            case _:
                return req


    def _apply_jwt_manipulation(
        self, plan: ConcreteExperimentPlan, sm: SessionManager
    ) -> NormalizedRequest:
        """Forge a manipulated JWT token and inject it into the Authorization header."""
        from hdwp.core.experiment.jwt_mutator import forge_alg_none, forge_expired, try_weak_secrets

        req = plan.baseline_request
        attack = plan.experiment_spec.mutation_params.get("jwt_attack", "alg_none")
        token = sm.build_auth_headers(plan.baseline_role).get("Authorization", "").replace("Bearer ", "")
        if not token:
            return req

        forged: str | None = None
        match attack:
            case "alg_none":
                forged = forge_alg_none(token)
            case "expired_token":
                forged = forge_expired(token)
            case "weak_secret":
                forged = try_weak_secrets(token)

        if forged is None:
            return req
        new_headers = {**req.headers, "Authorization": f"Bearer {forged}"}
        return req.model_copy(update={"headers": new_headers})

    def _apply_origin_test(self, plan: ConcreteExperimentPlan) -> NormalizedRequest:
        """Add a malicious Origin header to test CORS policy."""
        evil_origin = plan.experiment_spec.mutation_params.get(
            "evil_origin", "https://evil.hdwp-test.invalid"
        )
        new_headers = {**plan.baseline_request.headers, "Origin": evil_origin}
        return plan.baseline_request.model_copy(update={"headers": new_headers})


# ── URL helpers ───────────────────────────────────────────────────────────

def _replace_first_id_in_path(url: str, new_value: str) -> str:
    """
    Replace the first numeric or UUID path segment with new_value.
    /api/users/42/posts  →  /api/users/99/posts  (new_value="99")
    """
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    for i, part in enumerate(parts):
        if _NUMERIC.match(part) or _UUID.match(part):
            parts[i] = new_value
            break
    return urlunparse(parsed._replace(path="/".join(parts)))


def _rebuild_url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params)))
