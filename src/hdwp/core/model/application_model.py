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
    AUTH_REQUIRED,
    FINDING_REFUTED,
    FLOW_UPDATED,
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

_PII_FIELD_NAMES = frozenset({
    "email", "password", "passwd", "ssn", "phone", "address", "credit_card",
    "creditcard", "national_id", "dob", "date_of_birth", "passport", "tax_id",
    "private_key", "secret", "api_key", "apikey", "auth_token", "refresh_token",
    "access_token", "billing", "salary", "income",
})


def _infer_sensitivity(schema_def: dict) -> str:
    """Elevate DataObjectNode sensitivity to 'sensitive' if schema contains PII field names."""
    keys_lower = {k.lower() for k in schema_def} if isinstance(schema_def, dict) else set()
    if keys_lower & _PII_FIELD_NAMES:
        return "sensitive"
    return "public"


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
        # Tech stack et content types agrégés
        self._tech_stack: set[str] = set()
        self._detected_content_types: set[str] = set()

        # Flow map builder
        from hdwp.core.model.flow_map_builder import FlowMapBuilder
        self._flow_builder = FlowMapBuilder()
        self._last_flow_map = None
        self._obs_count: int = 0
        self._prev_fsm_changed: bool = False
        self._auth_notified: set[str] = set()

        self._confidence_weights: dict[str, float] = {"ep": 0.4, "role": 0.4, "bola": 0.2}
        # Behavioral profiling: track response size distribution per endpoint for Z-score anomaly detection
        self._behavioral_profiles: dict[str, dict] = {}

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

        # Behavioral profiling — update response size distribution for Z-score detection
        _current_path = self._normalize_path(obs.request.url)
        self._update_behavioral_profile(_current_path, obs.response.body if obs.response else None)

        # Flow map: track referrer edges and count observations
        self._flow_builder.add_observation(obs, _current_path)
        self._obs_count += 1

        # Extraire les liens depuis le body JSON pour enrichir le corpus avec
        # des endpoints non découverts par le crawl HTML (ex: HATEOAS links)
        for link_url in self._extract_links_from_body(obs):
            path_pattern = self._normalize_path(link_url)
            if path_pattern not in self._endpoints:
                # Ajouter l'URL au corpus sans émettre d'observation complète
                # (sera crawlé lors de la prochaine session si dans le scope)
                self._store_in_corpus_by_url(link_url, obs)

        # Agréger tech_stack depuis les tags d'observation (header_inspector)
        for tag in obs.tags:
            if tag.startswith(("server:", "framework:", "db:", "cms:")):
                self._tech_stack.add(tag)

        # Agréger content-type depuis la réponse
        if obs.response and obs.response.content_type:
            ct = obs.response.content_type.split(";")[0].strip().lower()
            if ct:
                self._detected_content_types.add(ct)
            # Propager vers l'endpoint
            path_pattern = self._normalize_path(obs.request.url)
            if path_pattern in self._endpoints:
                ep = self._endpoints[path_pattern]
                if not ep.response_content_type:
                    ep.response_content_type = ct
                if "xml" in ct:
                    ep.accepts_xml = True

        # Extraire les méthodes depuis le header Allow: des réponses OPTIONS
        # C'est le seul endroit où le serveur déclare explicitement les méthodes acceptées.
        if obs.request.method.upper() == "OPTIONS" and obs.response:
            allow_hdr = (obs.response.headers or {}).get("allow", "")
            if allow_hdr:
                path_pattern = self._normalize_path(obs.request.url)
                ep = self._endpoints.get(path_pattern)
                if ep is None:
                    ep = EndpointNode(path=path_pattern, methods=[])
                    self._endpoints[path_pattern] = ep
                for m in allow_hdr.replace(",", " ").split():
                    m = m.strip().upper()
                    if m and m not in ep.methods and m not in ("OPTIONS", "HEAD"):
                        ep.methods.append(m)

        changed = False
        changed |= self._update_endpoint(obs)
        changed |= self._update_parameters(obs)
        changed |= self._update_data_objects(obs)
        changed |= self._update_role(obs)
        changed |= await self._update_auth_required(obs)

        if changed:
            self._last_updated = obs.timestamp
            await self._bus.emit(
                MODEL_UPDATED,
                self.snapshot().model_dump(),
                source="application_model",
            )

        # Flow map rebuild (throttled: every 20 obs or when FSM changes)
        _fsm_changed = self._prev_fsm_changed
        self._prev_fsm_changed = False
        if self._flow_builder.should_rebuild(self._obs_count, _fsm_changed):
            flow_map = self._flow_builder.build(self.snapshot())
            self._last_flow_map = flow_map
            self._relations = [e.model_dump() for e in flow_map.edges]
            await self._bus.emit(FLOW_UPDATED, flow_map.model_dump(), source="flow_map_builder")

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
            self._prev_fsm_changed = True
            await self._bus.emit(MODEL_UPDATED, self.snapshot().model_dump(), source="application_model")

    # ── endpoint tracking ─────────────────────────────────

    def _update_endpoint(self, obs: RawObservation) -> bool:
        req = obs.request
        assert req is not None
        path_pattern = self._normalize_path(req.url)
        method = req.method.upper()

        is_graphql = "graphql" in path_pattern.lower()

        if path_pattern not in self._endpoints:
            self._endpoints[path_pattern] = EndpointNode(
                path=path_pattern, methods=[method], is_graphql=is_graphql,
            )
            return True

        ep = self._endpoints[path_pattern]
        changed = False
        if method not in ep.methods:
            ep.methods.append(method)
            changed = True
        if is_graphql and not ep.is_graphql:
            ep.is_graphql = True
            changed = True

        # Only link parameters that originate from THIS observation,
        # not all globally accumulated parameters (prevents cross-endpoint contamination).
        for key in self._obs_param_keys(req):
            param = self._parameters.get(key)
            if param and param.id not in ep.parameters:
                ep.parameters.append(param.id)
                changed = True

        return changed

    def _obs_param_keys(self, req: NormalizedRequest) -> list[str]:
        """Return the parameter store keys that come from this specific request."""
        keys: list[str] = []
        for name in req.query_params:
            keys.append(f"{name}:query")
        if isinstance(req.body, dict):
            for name in req.body:
                keys.append(f"{name}:body")
        parts = self._url_parts(req.url)
        for i, part in enumerate(parts):
            if _NUMERIC_RE.match(part) or _UUID_RE.match(part):
                keys.append(f"path_{i}:path")
        return keys

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
                    semantic=self._infer_semantic(name, self._infer_type(value)),
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
                        semantic=self._infer_semantic(name, self._infer_type(value)),
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
                        semantic="id_ref",
                    )
                    changed = True

        return changed

    @staticmethod
    def _infer_semantic(name: str, type_inferred: str) -> str | None:
        """Infer semantic category from parameter name."""
        n = name.lower()
        if re.search(r'\b(file|filename|filepath|dir|folder|document|resource|include|load|read|path)\b', n):
            return "file_path"
        if re.search(r'\b(url|redirect|next|return|goto|callback|dest|destination|target|forward|continue)\b', n):
            return "url_redirect"
        if re.search(r'\b(template|view|render|layout|theme|skin|widget|page)\b', n):
            return "template_expr"
        if re.search(r'\b(xml|soap|wsdl)\b', n):
            return "xml_input"
        if re.search(r'\b(password|passwd|secret|token|api_key|apikey|auth)\b', n):
            return "credential"
        if type_inferred in ("integer", "uuid"):
            return "id_ref"
        return None

    # ── data object inference ─────────────────────────────

    def _update_data_objects(self, obs: RawObservation) -> bool:
        resp = obs.response
        assert resp is not None
        if not isinstance(resp.body, dict):
            return False

        schema = {k: type(v).__name__ for k, v in resp.body.items()}
        schema_key = str(sorted((k, v) for k, v in schema.items()))

        if schema_key not in self._objects:
            obj = DataObjectNode(schema=schema, sensitivity=_infer_sensitivity(schema))
            self._objects[schema_key] = obj
            self._detect_affects_object(obs, obj)
            return True
        return False

    def _detect_affects_object(
        self, obs: RawObservation, obj: DataObjectNode
    ) -> None:
        """Mark path parameters that are numeric/UUID as object references.
        A numeric/UUID path segment is sufficient evidence of an object reference —
        no need to confirm the value appears in the response body."""
        req = obs.request
        assert req is not None
        parts = self._url_parts(req.url)
        for i, part in enumerate(parts):
            if _NUMERIC_RE.match(part) or _UUID_RE.match(part):
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

    async def _update_auth_required(self, obs: RawObservation) -> bool:
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
        elif anon_status in (401, 403) and not ep.roles_observed:
            # Auth requise mais aucun rôle authentifié connu : notifier l'utilisateur
            if path_pattern not in self._auth_notified:
                self._auth_notified.add(path_pattern)
                await self._bus.emit(
                    AUTH_REQUIRED,
                    {"url": req.url, "path_pattern": path_pattern},
                    source="application_model",
                )

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
            # Utiliser la méthode de la requête source qui a retourné ce lien HATEOAS.
            # Stocker systématiquement en GET masquait les endpoints découverts via POST.
            source_method = source_obs.request.method if source_obs.request else "GET"
            synthetic_req = normalize_request(method=source_method, url=url)
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

    def _update_behavioral_profile(self, path_pattern: str, response_body: object) -> None:
        """Track response size distribution for Z-score anomaly detection."""
        import math
        size = len(str(response_body)) if response_body is not None else 0
        profile = self._behavioral_profiles.setdefault(path_pattern, {"sizes": [], "mean": 0.0, "std": 1.0})
        profile["sizes"].append(size)
        sizes = profile["sizes"][-50:]  # rolling window of 50 observations
        profile["sizes"] = sizes
        if len(sizes) >= 3:
            mean = sum(sizes) / len(sizes)
            variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
            profile["mean"] = mean
            profile["std"] = max(math.sqrt(variance), 1.0)

    def get_response_zscore(self, path_pattern: str, response_body: object) -> float | None:
        """Return Z-score of response size vs historical distribution. None if < 5 observations."""
        profile = self._behavioral_profiles.get(path_pattern)
        if not profile or len(profile.get("sizes", [])) < 5:
            return None
        size = len(str(response_body)) if response_body is not None else 0
        return (size - profile["mean"]) / profile["std"]

    def get_corpus_for_path(self, path_pattern: str) -> list[tuple[str, NormalizedRequest]]:
        """Return observed requests for a given path pattern."""
        return self._request_corpus.get(path_pattern, [])

    def get_all_corpus(self) -> dict[str, list[tuple[str, NormalizedRequest]]]:
        """Return the full request corpus (path_pattern -> [(role, request)])."""
        return dict(self._request_corpus)

    # ── model readiness ───────────────────────────────────

    def set_confidence_weights(self, weights: dict[str, float]) -> None:
        self._confidence_weights = weights

    @property
    def model_confidence(self) -> float:
        """
        Confidence score [0..1] estimating how well the model covers the application.

        Three factors combined with KB-adapted weights:
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

        w = self._confidence_weights
        total = w.get("ep", 0.4) + w.get("role", 0.4) + w.get("bola", 0.2)
        if total == 0:
            total = 1.0
        return (w.get("ep", 0.4) * ep_cov + w.get("role", 0.4) * role_cov + w.get("bola", 0.2) * bola_cov) / total

    @property
    def is_ready(self) -> bool:
        """True when model_confidence ≥ 0.3 — enough coverage to start reasoning."""
        return self.model_confidence >= 0.3

    # ── public API ────────────────────────────────────────

    def get_flow_map(self):
        """Retourne le DataFlowMap courant (non inclus dans snapshot())."""
        return self._last_flow_map

    def snapshot(self) -> ApplicationModelData:
        return ApplicationModelData(
            endpoints=list(self._endpoints.values()),
            parameters=list(self._parameters.values()),
            objects=list(self._objects.values()),
            roles=list(self._roles.values()),
            relations=self._relations,
            last_updated=self._last_updated,
            fsm=self._fsm,
            tech_stack=sorted(self._tech_stack),
            detected_content_types=sorted(self._detected_content_types),
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
