# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import urlparse

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    FINDING_REFUTED,
    FSM_UPDATED,
    MODEL_UPDATED,
    OBSERVATION_RAW,
    HDWPEvent,
)
from hdwp.core.model.schemas import (
    ApplicationFSM,
    ApplicationModelData,
    DataObjectNode,
    EndpointNode,
    NormalizedRequest,
    ParameterNode,
    RawObservation,
    RoleNode,
)
from hdwp.core.model.url_utils import normalize_url_path

logger = structlog.get_logger()

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


class ApplicationModel:
    """Subscribes to observation.raw events and incrementally builds the
    behavioral graph. Publishes model.updated when the model changes."""

    def __init__(self, bus: AsyncEventBus) -> None:
        self._bus = bus
        self._endpoints: dict[str, EndpointNode] = {}
        self._parameters: dict[str, ParameterNode] = {}
        self._objects: dict[str, DataObjectNode] = {}
        self._roles: dict[str, RoleNode] = {}
        self._relations: list[dict[str, Any]] = []
        self._last_updated: str = ""
        # Corpus: path_pattern -> list of (role_name, NormalizedRequest)
        self._request_corpus: dict[str, list[tuple[str, NormalizedRequest]]] = {}
        # Auth detection: path_pattern -> role_name -> last observed status code
        self._status_by_role: dict[str, dict[str, int]] = {}
        # FSM apprise par StateMachineLearner
        self._fsm: ApplicationFSM | None = None

        bus.on(OBSERVATION_RAW, self._on_observation)
        bus.on(FINDING_REFUTED, self._on_finding_refuted)
        bus.on(FSM_UPDATED, self._on_fsm_updated)

    # ── event handlers ────────────────────────────────────

    async def _on_observation(self, event: HDWPEvent) -> None:
        obs = event.payload
        if isinstance(obs, dict):
            obs = RawObservation.model_validate(obs)
        elif not isinstance(obs, RawObservation):
            return

        if obs.request is None or obs.response is None:
            return

        self._store_in_corpus(obs)

        # Extraire les liens depuis le body JSON pour enrichir le corpus avec
        # des endpoints non découverts par le crawl HTML (ex: HATEOAS links)
        for link_url in self._extract_links_from_body(obs):
            path_pattern = self._normalize_path(link_url)
            if path_pattern not in self._endpoints:
                # Ajouter l'URL au corpus sans émettre d'observation complète
                # (sera crawlé lors de la prochaine session si dans le scope)
                self._store_in_corpus_by_url(link_url, obs)

        changed = False
        changed |= self._update_endpoint(obs)
        changed |= self._update_parameters(obs)
        changed |= self._update_data_objects(obs)
        changed |= self._update_role(obs)
        changed |= self._update_auth_required(obs)

        if changed:
            self._last_updated = obs.timestamp
            await self._bus.emit(
                MODEL_UPDATED,
                self.snapshot().model_dump(),
                source="application_model",
            )

    async def _on_finding_refuted(self, event: HDWPEvent) -> None:
        # Boucle d'apprentissage : une hypothèse réfutée signale que la propriété tient.
        # Les réponses d'expérience ont déjà été émises sur le bus et enrichissent
        # le corpus. En Phase 6, le StateMachineLearner affinera le modèle depuis ces
        # observations. Ici on journalise pour la traçabilité.
        data = event.payload
        if not isinstance(data, dict):
            return
        hyp_id = data.get("hypothesis_id", "unknown")
        logger.info("learning_loop.refuted", hypothesis_id=hyp_id)

    async def _on_fsm_updated(self, event: HDWPEvent) -> None:
        """Stocke la FSM apprise et propage model.updated seulement si la FSM a changé."""
        data = event.payload
        new_fsm = ApplicationFSM.model_validate(data) if isinstance(data, dict) else data
        # Éviter les cycles inutiles : n'émettre model.updated que si la FSM a réellement évolué
        if (
            self._fsm is None
            or len(new_fsm.states) != len(self._fsm.states)
            or len(new_fsm.transitions) != len(self._fsm.transitions)
        ):
            self._fsm = new_fsm
            self._last_updated = new_fsm.id
            await self._bus.emit(MODEL_UPDATED, self.snapshot().model_dump(), source="application_model")

    # ── endpoint tracking ─────────────────────────────────

    def _update_endpoint(self, obs: RawObservation) -> bool:
        req = obs.request
        assert req is not None
        path_pattern = self._normalize_path(req.url)
        method = req.method.upper()

        if path_pattern not in self._endpoints:
            self._endpoints[path_pattern] = EndpointNode(
                path=path_pattern, methods=[method]
            )
            return True

        ep = self._endpoints[path_pattern]
        changed = False
        if method not in ep.methods:
            ep.methods.append(method)
            changed = True

        for param in self._parameters.values():
            if param.id not in ep.parameters:
                ep.parameters.append(param.id)
                changed = True

        return changed

    # ── parameter tracking ────────────────────────────────

    def _update_parameters(self, obs: RawObservation) -> bool:
        req = obs.request
        assert req is not None
        changed = False

        for name, value in req.query_params.items():
            key = f"{name}:query"
            if key not in self._parameters:
                self._parameters[key] = ParameterNode(
                    name=name,
                    location="query",
                    type_inferred=self._infer_type(value),
                )
                changed = True

        if isinstance(req.body, dict):
            for name, value in req.body.items():
                key = f"{name}:body"
                if key not in self._parameters:
                    self._parameters[key] = ParameterNode(
                        name=name,
                        location="body",
                        type_inferred=self._infer_type(value),
                    )
                    changed = True

        parts = self._url_parts(req.url)
        for i, part in enumerate(parts):
            if _NUMERIC_RE.match(part) or _UUID_RE.match(part):
                key = f"path_{i}:path"
                if key not in self._parameters:
                    self._parameters[key] = ParameterNode(
                        name=f"path_{i}",
                        location="path",
                        type_inferred=self._infer_type(part),
                    )
                    changed = True

        return changed

    # ── data object inference ─────────────────────────────

    def _update_data_objects(self, obs: RawObservation) -> bool:
        resp = obs.response
        assert resp is not None
        if not isinstance(resp.body, dict):
            return False

        schema = {k: type(v).__name__ for k, v in resp.body.items()}
        schema_key = str(sorted((k, v) for k, v in schema.items()))

        if schema_key not in self._objects:
            obj = DataObjectNode(schema=schema, sensitivity="public")
            self._objects[schema_key] = obj
            self._detect_affects_object(obs, obj)
            return True
        return False

    def _detect_affects_object(
        self, obs: RawObservation, obj: DataObjectNode
    ) -> None:
        req = obs.request
        resp = obs.response
        assert req is not None and resp is not None
        if not isinstance(resp.body, dict):
            return

        resp_values = {str(v) for v in resp.body.values()}
        parts = self._url_parts(req.url)
        for i, part in enumerate(parts):
            if _NUMERIC_RE.match(part) and part in resp_values:
                key = f"path_{i}:path"
                if key in self._parameters:
                    self._parameters[key].affects_object = obj.id

    # ── role tracking ─────────────────────────────────────

    def _update_role(self, obs: RawObservation) -> bool:
        req = obs.request
        assert req is not None
        # Prefer role name from crawler tag (e.g. "role:user_a") over header detection,
        # because Authorization headers are redacted before reaching the model.
        role_name = "anonymous"
        for tag in obs.tags:
            if tag.startswith("role:"):
                role_name = tag[5:]
                break
        else:
            # Fallback: if Authorization header present (even redacted), mark as authenticated
            auth = req.headers.get("authorization") or req.headers.get("Authorization", "")
            if auth:
                role_name = f"authenticated_{obs.session_id[:8]}"

        created = False
        if role_name not in self._roles:
            self._roles[role_name] = RoleNode(name=role_name)
            created = True

        path_pattern = self._normalize_path(req.url)
        perm = f"{req.method.upper()}:{path_pattern}"
        role = self._roles[role_name]
        if perm not in role.observed_permissions:
            role.observed_permissions.append(perm)
            return True
        return created

    # ── auth_required auto-detection ──────────────────────

    def _update_auth_required(self, obs: RawObservation) -> bool:
        """
        Auto-détecte auth_required en comparant les status codes par rôle.

        Règle : si anonymous → 401/403 ET un rôle authentifié → 2xx pour le
        même path_pattern → auth_required = True, roles_observed mis à jour.
        """
        req = obs.request
        resp = obs.response
        if req is None or resp is None:
            return False

        path_pattern = self._normalize_path(req.url)
        role_name = "anonymous"
        for tag in obs.tags:
            if tag.startswith("role:"):
                role_name = tag[5:]
                break

        by_role = self._status_by_role.setdefault(path_pattern, {})
        by_role[role_name] = resp.status_code

        if path_pattern not in self._endpoints:
            return False

        ep = self._endpoints[path_pattern]
        anon_status = by_role.get("anonymous", 0)
        auth_successes = [
            r for r, s in by_role.items()
            if r != "anonymous" and 200 <= s < 300
        ]

        changed = False
        if anon_status in (401, 403) and auth_successes:
            if not ep.auth_required:
                ep.auth_required = True
                changed = True
            for role in auth_successes:
                if role not in ep.roles_observed:
                    ep.roles_observed.append(role)
                    changed = True

        return changed

    # ── corpus ────────────────────────────────────────────

    def _store_in_corpus(self, obs: RawObservation) -> None:
        """Store observed request in corpus indexed by path pattern (max 10 per pattern)."""
        req = obs.request
        if req is None:
            return
        path_pattern = self._normalize_path(req.url)
        role_name = "anonymous"
        for tag in obs.tags:
            if tag.startswith("role:"):
                role_name = tag[5:]
                break
        bucket = self._request_corpus.setdefault(path_pattern, [])
        if len(bucket) < 10:
            bucket.append((role_name, req))

    def _store_in_corpus_by_url(self, url: str, source_obs: RawObservation) -> None:
        """Ajoute une URL découverte (depuis le body d'une réponse) au corpus."""
        from hdwp.core.observation.normalizer import normalize_request
        path_pattern = self._normalize_path(url)
        bucket = self._request_corpus.setdefault(path_pattern, [])
        if len(bucket) < 10:
            role_name = next(
                (t[5:] for t in source_obs.tags if t.startswith("role:")), "anonymous"
            )
            synthetic_req = normalize_request(method="GET", url=url)
            bucket.append((role_name, synthetic_req))

    def _extract_links_from_body(self, obs: RawObservation) -> list[str]:
        """
        Extrait les URLs/paths depuis le body de réponse JSON.
        Utile pour les APIs HATEOAS qui exposent des liens dans leurs réponses.
        """
        resp = obs.response
        req = obs.request
        if resp is None or not isinstance(resp.body, dict) or req is None:
            return []
        from urllib.parse import urlparse
        parsed = urlparse(req.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        links: list[str] = []
        for value in resp.body.values():
            if isinstance(value, str):
                # Filtrer strict : doit ressembler à un endpoint REST, pas un Unix path
                if (value.startswith(("/api/", "/v", "/rest/", "/graphql")) and
                        len(value) > 4 and not value.startswith(("/var", "/usr", "/home", "/etc"))):
                    links.append(f"{base}{value}")
                elif value.startswith("http") and value.startswith(base):
                    links.append(value)
        return links

    def get_corpus_for_path(self, path_pattern: str) -> list[tuple[str, NormalizedRequest]]:
        """Return observed requests for a given path pattern."""
        return self._request_corpus.get(path_pattern, [])

    def get_all_corpus(self) -> dict[str, list[tuple[str, NormalizedRequest]]]:
        """Return the full request corpus (path_pattern -> [(role, request)])."""
        return dict(self._request_corpus)

    # ── model readiness ───────────────────────────────────

    @property
    def model_confidence(self) -> float:
        """
        Confidence score [0..1] estimating how well the model covers the application.

        Three factors combined:
        - endpoint_coverage : log(1+n) / log(11), saturates at 10 endpoints
        - role_coverage      : min(1.0, n_roles / 2), needs ≥2 roles
        - bola_coverage      : min(1.0, n_params_with_affects_object / 2)
        """
        n_endpoints = len(self._endpoints)
        n_roles = len(self._roles)
        n_bola = sum(1 for p in self._parameters.values() if p.affects_object)

        ep_cov = math.log(1 + n_endpoints) / math.log(11)
        role_cov = min(1.0, n_roles / 2)
        bola_cov = min(1.0, n_bola / 2)

        return 0.4 * ep_cov + 0.4 * role_cov + 0.2 * bola_cov

    @property
    def is_ready(self) -> bool:
        """True when model_confidence ≥ 0.3 — enough coverage to start reasoning."""
        return self.model_confidence >= 0.3

    # ── public API ────────────────────────────────────────

    def snapshot(self) -> ApplicationModelData:
        return ApplicationModelData(
            endpoints=list(self._endpoints.values()),
            parameters=list(self._parameters.values()),
            objects=list(self._objects.values()),
            roles=list(self._roles.values()),
            relations=self._relations,
            last_updated=self._last_updated,
            fsm=self._fsm,
        )

    def update_role_mapping(
        self, role_name: str, endpoint_key: str
    ) -> None:
        if role_name not in self._roles:
            self._roles[role_name] = RoleNode(name=role_name)
        role = self._roles[role_name]
        if endpoint_key not in role.observed_permissions:
            role.observed_permissions.append(endpoint_key)
        if role_name != "anonymous":
            for path, ep in self._endpoints.items():
                if path == endpoint_key or (ep.methods and f"{ep.methods[0]}:{ep.path}" == endpoint_key):
                    ep.auth_required = True
                    if role_name not in ep.roles_observed:
                        ep.roles_observed.append(role_name)

    # ── helpers ───────────────────────────────────────────

    @staticmethod
    def _normalize_path(url: str) -> str:
        """Delegates to url_utils.normalize_url_path for shared implementation."""
        return normalize_url_path(url)

    @staticmethod
    def _url_parts(url: str) -> list[str]:
        path = urlparse(url).path.strip("/")
        return path.split("/") if path else []

    @staticmethod
    def _infer_type(value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        s = str(value)
        if _NUMERIC_RE.match(s):
            return "integer"
        if _UUID_RE.match(s):
            return "uuid"
        if s.lower() in ("true", "false"):
            return "boolean"
        return "string"
