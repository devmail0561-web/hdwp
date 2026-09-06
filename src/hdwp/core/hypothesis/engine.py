# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDING_CONFIRMED, HYPOTHESIS_GENERATED, PROPERTY_INFERRED, HDWPEvent
from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
    generate_id,
)

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.plugins.registry import PluginRegistry
    from hdwp.store.repository import Repository

logger = structlog.get_logger()


def _expand_hypotheses_per_endpoint(
    hypotheses: list[Hypothesis],
    model: ApplicationModelData,
) -> list[Hypothesis]:
    """Duplique chaque hypothèse pour chaque endpoint qui possède le paramètre cible.

    Problème résolu : les plugins génèrent une hypothèse par paramètre (sans endpoint),
    mais `plan_field_injection` retourne seulement le premier corpus entry.
    Sans cette expansion, tous les endpoints avec `param=id` ne reçoivent qu'un test
    alors que le premier trouvé absorbe tous les tests SQLi, XSS, etc.

    Résultat : chaque (endpoint_path × mutation_type × param_name) est une hypothèse
    indépendante avec son propre cycle oracle.
    """
    # Construire un index param_id → liste d'endpoints
    param_to_endpoints: dict[str, list[str]] = {}
    for ep in (model.endpoints or []):
        for pid in (ep.parameters or []):
            param_to_endpoints.setdefault(pid, []).append(ep.path)

    # Construire un index param_name × location → liste de param_ids
    name_loc_to_ids: dict[tuple[str, str], list[str]] = {}
    for p in (model.parameters or []):
        name_loc_to_ids.setdefault((p.name, p.location), []).append(p.id)

    expanded: list[Hypothesis] = []
    for hyp in hypotheses:
        exps = hyp.required_experiments or []
        if not exps:
            expanded.append(hyp)
            continue

        # Vérifier si toutes les expériences ont déjà un endpoint_path
        already_scoped = all(
            exp.mutation_params.get("endpoint_path")
            or exp.mutation_params.get("target_endpoint")
            for exp in exps
        )
        if already_scoped:
            expanded.append(hyp)
            continue

        # Trouver les endpoints concernés par le premier experiment avec param_name
        first_exp = exps[0]
        param_name = first_exp.mutation_params.get("parameter_name", "")
        param_loc = first_exp.mutation_params.get("parameter_location", "query")

        if not param_name:
            expanded.append(hyp)
            continue

        # Résoudre les endpoints via param_id → endpoint
        param_ids = name_loc_to_ids.get((param_name, param_loc), [])
        endpoint_paths: list[str] = []
        for pid in param_ids:
            endpoint_paths.extend(param_to_endpoints.get(pid, []))

        # Dédupliquer en préservant l'ordre
        seen: set[str] = set()
        unique_endpoints = [p for p in endpoint_paths if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]

        if not unique_endpoints:
            # Paramètre sans endpoint connu — conserver l'hypothèse telle quelle
            expanded.append(hyp)
            continue

        # Créer une hypothèse par endpoint
        for ep_path in unique_endpoints:
            new_exps = []
            for exp in exps:
                new_params = {**exp.mutation_params, "endpoint_path": ep_path}
                new_exps.append(exp.model_copy(update={"mutation_params": new_params}))

            new_hyp = hyp.model_copy(update={
                "id": generate_id("HYP"),
                "statement": f"[{ep_path}] {hyp.statement}",
                "required_experiments": new_exps,
            })
            expanded.append(new_hyp)

    return expanded


class HypothesisEngine:
    """
    Subscribes to property.inferred events.
    For each SecurityProperty, generates falsifiable hypotheses.
    Publishes hypothesis.generated events.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        model_accessor: Callable[[], ApplicationModelData | None] | None = None,
        plugin_registry: PluginRegistry | None = None,
        repository: Repository | None = None,
        prioritizer: HypothesisPrioritizer | None = None,
        llm_layer: LLMLayerProtocol | None = None,
    ) -> None:
        self._bus = bus
        self._hypotheses: dict[str, Hypothesis] = {}
        # Clés de déduplication : (endpoint_path, mutation_type, param_name)
        # Plus précis que (property_id, statement) qui laisse passer des doublons
        self._seen_keys: set[tuple[str, str, str]] = set()
        self._prioritizer = prioritizer or HypothesisPrioritizer()
        self._model_accessor = model_accessor
        self._plugin_registry = plugin_registry
        self._repository = repository
        self._llm_layer = llm_layer
        bus.on(PROPERTY_INFERRED, self._on_property_inferred)
        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)

    async def _on_property_inferred(self, event: HDWPEvent) -> None:
        prop_data = event.payload
        if isinstance(prop_data, dict):
            prop = SecurityProperty.model_validate(prop_data)
        else:
            prop = prop_data

        hypotheses = self._generate_hypotheses(prop)

        # Also ask plugins if a model snapshot is available
        if self._plugin_registry is not None and self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                for plugin in self._plugin_registry.list_enabled():
                    try:
                        plugin_hyps = plugin.generate_hypotheses(model)
                        # Expand each hypothesis to be endpoint-specific:
                        # une hypothèse sans endpoint_path dans ses expériences est
                        # dupliquée pour chaque endpoint qui possède le paramètre cible.
                        # Cela garantit que TOUTES les vulnérabilités sont testées sur
                        # CHAQUE endpoint, pas seulement sur le premier match du corpus.
                        expanded = _expand_hypotheses_per_endpoint(plugin_hyps, model)
                        hypotheses.extend(expanded)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("plugin.generate_hypotheses_failed", plugin_id=plugin.id, error=str(exc))

        # LLM complementary hypotheses (ADR-002 : informationnelles, required_experiments=[])
        if self._llm_layer is not None and self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                try:
                    statements = await self._llm_layer.propose_hypotheses(model, len(self._hypotheses))
                    for stmt in statements:
                        hyp = Hypothesis(
                            source_plugin="llm",
                            property_id=prop.id,
                            statement=stmt,
                            priority="LOW",
                            priority_rationale="LLM complementary hypothesis — ADR-002",
                            required_experiments=[],
                        )
                        if not self._is_duplicate(hyp):
                            hypotheses.append(hyp)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("llm.propose_hypotheses_error", error=str(exc))

        for hyp in hypotheses:
            if not self._is_duplicate(hyp):
                self._hypotheses[hyp.id] = hyp
                self._register_hypothesis_keys(hyp)
                if self._repository is not None:
                    try:
                        await self._repository.save_hypothesis(hyp)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("hypothesis.save_failed", hypothesis_id=hyp.id, error=str(exc))
                await self._bus.emit(
                    HYPOTHESIS_GENERATED, hyp.model_dump(), source="hypothesis_engine"
                )

    def _generate_hypotheses(self, prop: SecurityProperty) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        if prop.type == PropertyType.AUTHORIZATION:
            stmt_lower = prop.formal_statement.lower()
            if ("parameter" in stmt_lower or "access(s, resource)" in stmt_lower
                    or "bola" in stmt_lower or "ownership" in stmt_lower
                    or "object level" in stmt_lower):
                priority, rationale = self._prioritizer.compute_priority(
                    property_type=prop.type,
                    affected_node_count=len(prop.model_nodes),
                    total_endpoints=max(len(prop.model_nodes), 1),
                    observation_count=len(prop.source_observations),
                )
                hypotheses.append(
                    Hypothesis(
                        source_plugin="core.hypothesis_engine",
                        property_id=prop.id,
                        statement=(
                            f"The property '{prop.formal_statement}' can be violated "
                            "by swapping identity credentials while accessing the same resource."
                        ),
                        priority=priority,
                        priority_rationale=rationale,
                        required_experiments=[
                            ExperimentSpec(
                                mutation_type="identity_swap",
                                base_request=NormalizedRequest(method="", url=""),
                                mutation_params={
                                    "property_id": prop.id,
                                    "model_nodes": prop.model_nodes,
                                },
                                description="Swap auth credentials and attempt same resource access",
                            ),
                            ExperimentSpec(
                                mutation_type="object_ref_change",
                                base_request=NormalizedRequest(method="", url=""),
                                mutation_params={
                                    "property_id": prop.id,
                                    "model_nodes": prop.model_nodes,
                                },
                                description="Change object reference ID while keeping same auth",
                            ),
                        ],
                    )
                )

            if "role" in stmt_lower and "cannot access" in stmt_lower:
                priority, rationale = self._prioritizer.compute_priority(
                    property_type=prop.type,
                    affected_node_count=len(prop.model_nodes),
                    total_endpoints=max(len(prop.model_nodes), 1),
                    observation_count=len(prop.source_observations),
                )
                # Derive endpoint_path and target_role from model snapshot
                if self._model_accessor is None:
                    return hypotheses
                model = self._model_accessor()
                # Guard: model may be None if the ApplicationModel hasn't been
                # populated yet (e.g. property event fires before any observation).
                if model is None:
                    return hypotheses
                endpoint_path = ""
                for ep in model.endpoints:
                    if any(n in prop.model_nodes for n in ([ep.id] + ep.parameters)):
                        endpoint_path = ep.path
                        break
                # Pick least-privileged role as attacker
                role_names = [r.name for r in model.roles]
                target_role = "anonymous" if "anonymous" in role_names else (role_names[0] if role_names else "anonymous")
                if endpoint_path:
                    hypotheses.append(
                        Hypothesis(
                            source_plugin="core.hypothesis_engine",
                            property_id=prop.id,
                            statement=(
                                f"The property '{prop.formal_statement}' can be violated "
                                "by using a lower-privilege role's credentials on a restricted endpoint."
                            ),
                            priority=priority,
                            priority_rationale=rationale,
                            required_experiments=[
                                ExperimentSpec(
                                    mutation_type="privilege_escalation",
                                    base_request=NormalizedRequest(method="", url=""),
                                    mutation_params={
                                        "property_id": prop.id,
                                        "endpoint_path": endpoint_path,
                                        "target_role": target_role,
                                        "model_nodes": prop.model_nodes,
                                    },
                                    description=f"Access '{endpoint_path}' with role '{target_role}'",
                                ),
                            ],
                        )
                    )

        elif prop.type == PropertyType.INTEGRITY:
            param_name = self._extract_param_name(prop.formal_statement)
            param_location = self._extract_param_location(prop.formal_statement)
            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )

            if param_name and "does not accept unexpected fields" not in prop.formal_statement:
                # Injection classique : SQLi, XSS, SSTI
                experiments = [
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "' OR '1'='1",
                            "payload_type": "sqli",
                        },
                        description=f"SQLi probe on '{param_name}'",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "<script>alert(1)</script>",
                            "payload_type": "xss",
                        },
                        description=f"XSS probe on '{param_name}'",
                    ),
                    ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_location,
                            "payload": "{{7*7}}",
                            "payload_type": "ssti",
                            "expected_result": "49",
                        },
                        description=f"SSTI probe on '{param_name}'",
                    ),
                ]
                hypotheses.append(Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=f"Le paramètre '{param_name}' est vulnérable à une injection.",
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=experiments,
                ))

            elif "does not accept unexpected fields" in prop.formal_statement:
                # Mass assignment
                hypotheses.append(Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement="L'endpoint accepte des champs supplémentaires non prévus (mass assignment).",
                    priority="MEDIUM",
                    priority_rationale="Mass assignment potentiel sur endpoint POST/PUT",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="POST", url=""),
                        mutation_params={
                            "parameter_name": "is_admin",
                            "parameter_location": "body",
                            "payload": "true",
                            "payload_type": "mass_assign",
                            "extra_field": "is_admin",
                        },
                        description="Mass assignment probe: inject is_admin=true in body",
                    )],
                ))

        elif prop.type == PropertyType.COHERENCE:
            # Business invariant uniquement (CORS/headers n'ont pas de mutation active)
            if "business invariant" not in prop.formal_statement:
                return hypotheses

            model = self._model_accessor() if self._model_accessor else None
            if model is None:
                return hypotheses

            param_nodes = set(prop.model_nodes)
            target_param = next(
                (p for p in model.parameters if p.id in param_nodes),
                None,
            )
            if target_param is None:
                return hypotheses

            business_probes = [
                ("0",       "boundary", "business boundary: zero value"),
                ("-1",      "boundary", "business boundary: negative"),
                ("-9999",   "boundary", "business boundary: large negative"),
                ("0.001",   "boundary", "business boundary: fractional"),
                ("9999999", "boundary", "business boundary: overflow"),
            ]

            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )

            hypotheses.append(
                Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=(
                        f"Business logic flaw: parameter '{target_param.name}' accepts "
                        f"invalid values (zero/negative/overflow) without proper validation"
                    ),
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "parameter_name": target_param.name,
                                "parameter_location": target_param.location,
                                "payload": probe_val,
                                "payload_type": probe_type,
                                "expected_result": "",
                            },
                            description=probe_desc,
                        )
                        for probe_val, probe_type, probe_desc in business_probes
                    ],
                )
            )

        elif prop.type == PropertyType.CONFIDENTIALITY:
            priority, rationale = self._prioritizer.compute_priority(
                property_type=prop.type,
                affected_node_count=len(prop.model_nodes),
                total_endpoints=max(len(prop.model_nodes), 1),
                observation_count=len(prop.source_observations),
            )
            hypotheses.append(
                Hypothesis(
                    source_plugin="core.hypothesis_engine",
                    property_id=prop.id,
                    statement=(
                        f"The property '{prop.formal_statement}' can be violated "
                        "by querying another user's data."
                    ),
                    priority=priority,
                    priority_rationale=rationale,
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="identity_swap",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "property_id": prop.id,
                                "model_nodes": prop.model_nodes,
                            },
                            description="Query resource with different identity",
                        ),
                    ],
                )
            )

        # Method fuzzing : tester toutes les méthodes HTTP sur chaque endpoint
        if self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                for ep in model.endpoints[:10]:
                    hypotheses.append(Hypothesis(
                        source_plugin="core.hypothesis_engine",
                        property_id=f"PROP-methodfuzz-{ep.id}",
                        statement=f"L'endpoint {ep.path} n'est accessible qu'aux méthodes documentées",
                        priority="MEDIUM",
                        priority_rationale="Method fuzzing : test des méthodes non documentées",
                        required_experiments=[ExperimentSpec(
                            mutation_type="http_method_fuzzing",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={"endpoint_path": ep.path},
                            description=f"Test toutes les méthodes HTTP sur {ep.path}",
                        )],
                    ))

        return hypotheses

    @staticmethod
    def _extract_param_name(statement: str) -> str | None:
        """Extract param name from "input('name', location=...)" statement."""
        import re
        m = re.search(r"input\('([^']+)'", statement)
        return m.group(1) if m else None

    @staticmethod
    def _extract_param_location(statement: str) -> str:
        """Extract location from "location='...'" in statement."""
        import re
        m = re.search(r"location='([^']+)'", statement)
        return m.group(1) if m else "query"

    async def _on_finding_confirmed(self, event: HDWPEvent) -> None:
        """Boucle de feedback : quand un finding est confirmé, générer des hypothèses d'approfondissement.

        Exemple : SQLi confirmée sur /api/users?id → générer hypothèses stacked queries,
        time-based sur d'autres paramètres, UNION SELECT multi-colonnes.
        C'est ce qui différencie HDWP d'un scanner : il capitalise sur ses propres découvertes.
        """
        data = event.payload
        if not isinstance(data, dict):
            return

        mutation_type = data.get("proof", {}).get("mutation_type", "") if isinstance(data.get("proof"), dict) else ""
        cwe_id = data.get("cwe_id", "")
        endpoints = data.get("affected_endpoints", [])
        if not endpoints:
            return
        endpoint = endpoints[0]

        followup: list[Hypothesis] = []

        # SQLi confirmée → approfondir avec des techniques avancées
        # Bug fix: "sql" in mutation_type.lower() est dead code quand mutation_type="field_injection"
        # Fix: utiliser cwe_id pour détecter SQLi
        if mutation_type == "field_injection" and cwe_id in ("CWE-89",):
            proof = data.get("proof", {})
            wr = proof.get("winning_request") or {} if isinstance(proof, dict) else {}
            # Bug fix: body peut être string ou list — ne pas appeler .keys() sur un non-dict
            body = wr.get("body") if isinstance(wr, dict) else None
            body_keys = list(body.keys()) if isinstance(body, dict) else []
            query_keys = list((wr.get("query_params") or {}).keys()) if isinstance(wr, dict) else []
            params = query_keys or body_keys
            param_name = params[0] if params else "id"
            param_loc = "query" if wr.get("query_params") and param_name in (wr.get("query_params") or {}) else "body"

            advanced_sqli = [
                ("1'; SELECT table_name FROM information_schema.tables LIMIT 5--", "sqli_schema_enum"),
                ("1' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "sqli_union_5col"),
                ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "sqli_error_based"),
                ("1' OR SLEEP(10)--", "sqli_blind_10s"),
            ]
            for payload, p_type in advanced_sqli:
                hyp = Hypothesis(
                    source_plugin="hypothesis_engine.followup",
                    property_id="",
                    statement=f"[FOLLOWUP SQLi] [{endpoint}] {param_name} → {p_type}",
                    priority="HIGH",
                    priority_rationale="Approfondissement post-confirmation SQLi",
                    required_experiments=[ExperimentSpec(
                        mutation_type="field_injection",
                        base_request=NormalizedRequest(method="", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": param_loc,
                            "payload": payload,
                            "payload_type": "sqli",
                            "endpoint_path": endpoint,
                        },
                        description=f"SQLi follow-up: {p_type}",
                    )],
                )
                followup.append(hyp)

        # BOLA/IDOR confirmée → tester d'autres endpoints avec le même pattern
        if cwe_id == "CWE-639":
            idor_variants = [
                ("0", "idor_zero"),
                ("-1", "idor_negative"),
                ("999999", "idor_large"),
            ]
            proof = data.get("proof", {})
            wr = proof.get("winning_request") or {} if isinstance(proof, dict) else {}
            params = list((wr.get("query_params") or {}).keys()) if isinstance(wr, dict) else []
            param_name = params[0] if params else "id"
            for val, label in idor_variants:
                hyp = Hypothesis(
                    source_plugin="hypothesis_engine.followup",
                    property_id="",
                    statement=f"[FOLLOWUP BOLA] [{endpoint}] {param_name}={val} → {label}",
                    priority="HIGH",
                    priority_rationale="Énumération post-confirmation BOLA",
                    required_experiments=[ExperimentSpec(
                        mutation_type="object_ref_change",
                        base_request=NormalizedRequest(method="", url=""),
                        mutation_params={
                            "parameter_name": param_name,
                            "parameter_location": "query",
                            "target_value": val,
                            "endpoint_path": endpoint,
                        },
                        description=f"BOLA variant: {param_name}={val}",
                    )],
                )
                followup.append(hyp)

        # Enregistrer les hypothèses de suivi non-dupliquées
        for hyp in followup:
            if not self._is_duplicate(hyp):
                self._hypotheses[hyp.id] = hyp
                self._register_hypothesis_keys(hyp)
                if self._repository is not None:
                    try:
                        await self._repository.save_hypothesis(hyp)
                    except Exception:  # noqa: BLE001
                        pass
                await self._bus.emit(HYPOTHESIS_GENERATED, hyp.model_dump(), source="hypothesis_engine")

    def _is_duplicate(self, hyp: Hypothesis) -> bool:
        """Déduplique par (endpoint_path, mutation_type, param_name).

        La clé structurée n'est utilisée que si l'endpoint est connu (ep non-vide).
        Sans endpoint, on tombe sur la comparaison de statement — ce qui distingue
        correctement "/api/users vulnérable à sqli" de "/api/orders vulnérable à sqli".
        Sans cette règle, ("", "sqli", "id") bloquerait le test SQLi sur tous les
        endpoints ayant un paramètre "id".
        """
        for exp in (hyp.required_experiments or []):
            ep = (
                exp.mutation_params.get("endpoint_path", "")
                or exp.mutation_params.get("target_endpoint", "")
                or exp.mutation_params.get("authenticated_endpoint", "")
            )
            # Clé structurée UNIQUEMENT si l'endpoint est connu
            if ep:
                param = exp.mutation_params.get("parameter_name", "")
                if (ep, exp.mutation_type, param) in self._seen_keys:
                    return True
        # Fallback sur statement — distingue les endpoints différents
        return any(
            existing.statement == hyp.statement
            for existing in self._hypotheses.values()
        )

    def _register_hypothesis_keys(self, hyp: Hypothesis) -> None:
        """Enregistre les clés de déduplication pour une hypothèse acceptée."""
        for exp in (hyp.required_experiments or []):
            ep = (
                exp.mutation_params.get("endpoint_path", "")
                or exp.mutation_params.get("target_endpoint", "")
                or exp.mutation_params.get("authenticated_endpoint", "")
            )
            # N'enregistrer que si l'endpoint est connu — évite les faux positifs cross-endpoint
            if ep:
                param = exp.mutation_params.get("parameter_name", "")
                self._seen_keys.add((ep, exp.mutation_type, param))

    @property
    def hypotheses(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def get_pending(self) -> list[Hypothesis]:
        """Get pending hypotheses sorted by priority (HIGH first)."""
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        pending = [
            h
            for h in self._hypotheses.values()
            if h.status == HypothesisStatus.PENDING
        ]
        return sorted(pending, key=lambda h: priority_order.get(h.priority, 3))
