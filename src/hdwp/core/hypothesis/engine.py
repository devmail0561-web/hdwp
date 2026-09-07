# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    HYPOTHESIS_AMBIGUOUS,
    HYPOTHESIS_GENERATED,
    PROPERTY_INFERRED,
    HDWPEvent,
)
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
        from hdwp.core.hypothesis.bandit import HypothesisBandit
        self._bandit = HypothesisBandit()
        self._method_fuzz_done: bool = False  # généré une seule fois par session
        # (endpoint_hash, mutation_type:payload_type) → [confidence_0, confidence_1, ...]
        self._refuted_by_surface: dict[tuple[str, str], list[float]] = {}
        bus.on(PROPERTY_INFERRED, self._on_property_inferred)
        bus.on(FINDING_CONFIRMED, self._on_finding_confirmed)
        bus.on(FINDING_REFUTED, self._on_finding_refuted)
        bus.on(HYPOTHESIS_AMBIGUOUS, self._on_hypothesis_ambiguous_bandit)

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
                # Stamper property_type pour le bandit (arm key)
                if hyp.property_type is None and prop is not None:
                    hyp = hyp.model_copy(update={"property_type": prop.type.value})
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

        # Method fuzzing : généré une seule fois par session (évite O(n_props × n_endpoints) doublons)
        if not self._method_fuzz_done and self._model_accessor is not None:
            model = self._model_accessor()
            if model is not None:
                self._method_fuzz_done = True
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
        """Boucle de feedback : capitalise sur les findings confirmés pour explorer plus loin.

        Trois niveaux d'approfondissement :
        1. Techniques avancées sur le paramètre confirmé (ex: stacked queries après SQLi)
        2. Tous les paramètres de la requête gagnante, pas seulement le premier
        3. Endpoints frères partageant le même paramètre vulnérable (via _expand_hypotheses_per_endpoint)
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

        # Mise à jour bandit : CONFIRMED = reward maximal
        property_type = data.get("property_type") or ""
        self._bandit.update(property_type, mutation_type, "CONFIRMED")

        # Charger le modèle courant pour la découverte d'endpoints frères
        model = self._model_accessor() if self._model_accessor else None

        followup: list[Hypothesis] = []

        # ── SQLi confirmée → techniques avancées sur tous les params + endpoints frères ──
        if mutation_type == "field_injection" and cwe_id == "CWE-89":
            proof = data.get("proof", {})
            wr = proof.get("winning_request") or {} if isinstance(proof, dict) else {}
            body = wr.get("body") if isinstance(wr, dict) else None
            body_keys = list(body.keys()) if isinstance(body, dict) else []
            query_keys = list((wr.get("query_params") or {}).keys()) if isinstance(wr, dict) else []
            # Tous les paramètres, pas seulement le premier
            all_params = query_keys + [k for k in body_keys if k not in query_keys]
            if not all_params:
                all_params = ["id"]

            advanced_sqli = [
                ("1'; SELECT table_name FROM information_schema.tables LIMIT 5--", "sqli_schema_enum"),
                ("1' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "sqli_union_5col"),
                ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "sqli_error_based"),
                ("1' OR SLEEP(10)--", "sqli_blind_10s"),
            ]
            for param_name in all_params:
                param_loc = "query" if param_name in (wr.get("query_params") or {}) else "body"
                for payload, p_type in advanced_sqli:
                    followup.append(Hypothesis(
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
                    ))

                # Endpoints frères : même param, autres endpoints
                if model is not None:
                    sibling_probe = Hypothesis(
                        source_plugin="hypothesis_engine.followup",
                        property_id="",
                        statement=f"[FOLLOWUP SQLi] {param_name} sibling probe",
                        priority="MEDIUM",
                        priority_rationale="Scan des endpoints frères post-SQLi",
                        required_experiments=[ExperimentSpec(
                            mutation_type="field_injection",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "parameter_name": param_name,
                                "parameter_location": param_loc,
                                "payload": "' OR '1'='1",
                                "payload_type": "sqli_probe",
                            },
                            description="SQLi sibling probe",
                        )],
                    )
                    for h in _expand_hypotheses_per_endpoint([sibling_probe], model):
                        ep_path = h.required_experiments[0].mutation_params.get("endpoint_path", "")
                        if ep_path and ep_path != endpoint:
                            followup.append(h)

        # ── BOLA/IDOR confirmée → variantes d'IDs + endpoints frères ──
        if cwe_id == "CWE-639":
            proof = data.get("proof", {})
            wr = proof.get("winning_request") or {} if isinstance(proof, dict) else {}
            query_keys = list((wr.get("query_params") or {}).keys()) if isinstance(wr, dict) else []
            body = wr.get("body") if isinstance(wr, dict) else None
            body_keys = list(body.keys()) if isinstance(body, dict) and body else []
            all_params = query_keys or body_keys or ["id"]

            idor_variants = [("0", "idor_zero"), ("-1", "idor_negative"), ("999999", "idor_large")]

            for param_name in all_params:
                param_loc = "query" if param_name in (wr.get("query_params") or {}) else "path"
                for val, label in idor_variants:
                    followup.append(Hypothesis(
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
                                "parameter_location": param_loc,
                                "target_value": val,
                                "endpoint_path": endpoint,
                            },
                            description=f"BOLA variant: {param_name}={val}",
                        )],
                    ))

                # Endpoints frères : `_expand_hypotheses_per_endpoint` trouve tous les
                # endpoints qui exposent le même paramètre — cœur du pattern BOLA
                if model is not None:
                    sibling_probe = Hypothesis(
                        source_plugin="hypothesis_engine.followup",
                        property_id="",
                        statement=f"[FOLLOWUP BOLA] {param_name} sibling scan",
                        priority="HIGH",
                        priority_rationale="Scan des endpoints frères post-BOLA",
                        required_experiments=[ExperimentSpec(
                            mutation_type="object_ref_change",
                            base_request=NormalizedRequest(method="", url=""),
                            mutation_params={
                                "parameter_name": param_name,
                                "parameter_location": param_loc,
                            },
                            description="BOLA sibling scan",
                        )],
                    )
                    for h in _expand_hypotheses_per_endpoint([sibling_probe], model):
                        ep_path = h.required_experiments[0].mutation_params.get("endpoint_path", "")
                        if ep_path and ep_path != endpoint:
                            followup.append(h)

        # ── Privilege escalation confirmée → scanner les endpoints admin ──
        if mutation_type == "privilege_escalation" and model is not None:
            _ADMIN_PATTERNS = ("/admin", "/manage", "/internal", "/staff", "/superuser", "/root", "/system")
            for ep in model.endpoints:
                if ep.path == endpoint:
                    continue
                if any(pat in ep.path.lower() for pat in _ADMIN_PATTERNS):
                    followup.append(Hypothesis(
                        source_plugin="hypothesis_engine.followup",
                        property_id="",
                        statement=f"[FOLLOWUP PRIVESC] [{ep.path}] privilege escalation scan",
                        priority="HIGH",
                        priority_rationale="Scan admin post-confirmation privilege escalation",
                        required_experiments=[ExperimentSpec(
                            mutation_type="privilege_escalation",
                            base_request=NormalizedRequest(
                                method=ep.methods[0] if ep.methods else "GET", url=ep.path
                            ),
                            mutation_params={
                                "endpoint_path": ep.path,
                                "method": ep.methods[0] if ep.methods else "GET",
                            },
                            description=f"Privilege escalation follow-up: {ep.path}",
                        )],
                    ))

        # ── Enregistrer les hypothèses de suivi non-dupliquées ──
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

    async def _on_finding_refuted(self, event: HDWPEvent) -> None:
        """Mise à jour bandit + pivot stratégique si seuil de refutations atteint."""
        from hdwp.core.hypothesis.strategy_pivot import (
            endpoint_hash, generate_pivot_hypotheses, should_pivot,
        )

        data = event.payload
        if not isinstance(data, dict):
            return

        proof = data.get("proof", {}) if isinstance(data.get("proof"), dict) else {}
        mutation_type = proof.get("mutation_type", "")
        payload_type = proof.get("payload_type", "")
        property_type = data.get("property_type") or ""
        confidence = data.get("confidence", 0.5)
        endpoints = data.get("affected_endpoints", [])
        endpoint = endpoints[0] if endpoints else ""

        # Mise à jour bandit
        self._bandit.update(property_type, mutation_type, "REFUTED")

        if not endpoint or not mutation_type:
            return

        # Tracker les refutations par surface (endpoint_hash, mutation_type:payload_type)
        surface_key = (endpoint_hash(endpoint), f"{mutation_type}:{payload_type}" if payload_type else mutation_type)
        bucket = self._refuted_by_surface.setdefault(surface_key, [])
        bucket.append(float(confidence))

        # Déclencher un pivot si le seuil est atteint
        if should_pivot(bucket) and self._model_accessor:
            model = self._model_accessor()
            if model is not None:
                pivot_hyps = generate_pivot_hypotheses(endpoint, mutation_type, proof, model)
                for hyp in pivot_hyps:
                    if not self._is_duplicate(hyp):
                        self._hypotheses[hyp.id] = hyp
                        self._register_hypothesis_keys(hyp)
                        if self._repository is not None:
                            try:
                                await self._repository.save_hypothesis(hyp)
                            except Exception:  # noqa: BLE001
                                pass
                        await self._bus.emit(
                            HYPOTHESIS_GENERATED, hyp.model_dump(), source="strategy_pivot"
                        )
                        logger.info(
                            "strategy_pivot.generated",
                            from_mutation=mutation_type,
                            endpoint=endpoint,
                            pivot_mutation=hyp.required_experiments[0].mutation_type if hyp.required_experiments else "",
                        )

    async def _on_hypothesis_ambiguous_bandit(self, event: HDWPEvent) -> None:
        """Mise à jour bandit sur verdict AMBIGUOUS (sans déclencher le resolver — celui-ci a son propre abonnement)."""
        payload = event.payload
        if not isinstance(payload, dict):
            return
        mutation_type = payload.get("mutation_type", "")
        score = payload.get("score", 0.3)
        # property_type n'est pas dans le payload HYPOTHESIS_AMBIGUOUS — récupérer depuis l'hypothèse en mémoire
        hyp_id = payload.get("hypothesis_id", "")
        hyp = self._hypotheses.get(hyp_id)
        property_type = hyp.property_type or "" if hyp else ""
        self._bandit.update(property_type, mutation_type, "INSUFFICIENT_DATA", score=score)

    @property
    def bandit(self) -> object:
        """Expose le bandit pour les stats CLI."""
        return self._bandit

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
        """
        Retourne les hypothèses PENDING ordonnées par Thompson Sampling.
        Le bandit apprend quels (property_type, mutation_type) sont fructueux
        et les favorise, tout en maintenant une exploration probabiliste.
        Les hypothèses HIGH restent boosted (+0.3) mais ne sont plus garanties premières.
        """
        pending = [h for h in self._hypotheses.values() if h.status == HypothesisStatus.PENDING]
        return self._bandit.sort(pending)
