# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MutationRegistry: registre centralise de toutes les mutations.

Elimine les match hard-codes eparpilles dans 6 fichiers.
Chaque mutation est definie une seule fois ici.
Les plugins peuvent enregistrer de nouvelles mutations via register().
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from hdwp.core.experiment.mutation_types import ApplyFunction, PlanFunction
    from hdwp.core.experiment.session_manager import SessionManager
    from hdwp.core.model.schemas import (
        ApplicationModelData,
        ConcreteExperimentPlan,
        ExperimentSpec,
        Hypothesis,
        NormalizedRequest,
    )
    from hdwp.core.oracle.violation_oracle import ViolationAssessment

log = structlog.get_logger()


@dataclass
class MutationSpec:
    """Definition complete d'un type de mutation."""

    name: str
    owasp_category: str
    cwe_id: str
    remediation: str
    # Le callable recoid (baseline, experiment, diff) -> ViolationAssessment
    assess_violation: Callable[..., ViolationAssessment] = field(repr=False)
    # Le callable recoid (mutation_type, diff, experiment, assessment) -> float
    compute_specificity: Callable[..., float] = field(repr=False)
    # Planification : (hypothesis, spec, model, corpus) -> list[ConcreteExperimentPlan]
    plan_experiment: PlanFunction | None = field(default=None, repr=False)
    # Application : (plan, session_manager) -> NormalizedRequest
    apply_mutation: ApplyFunction | None = field(default=None, repr=False)


# Forward reference pour eviter les imports circulaires
_violation_assessors: dict[str, Callable[..., object]] = {}
_specificity_computers: dict[str, Callable[..., float]] = {}


def _lazy_assess(name: str, baseline: object, experiment: object, diff: object) -> ViolationAssessment:
    """Assess violation en lazy-loadant les assesseurs."""
    if not _violation_assessors:
        from hdwp.core.oracle.violation_oracle import (
            _assess_cors,
            _assess_field_injection,
            _assess_identity_swap,
            _assess_jwt_manipulation,
            _assess_object_ref_change,
            _assess_privilege_escalation,
        )

        _violation_assessors.update(
            {
                "identity_swap": _assess_identity_swap,
                "object_ref_change": _assess_object_ref_change,
                "privilege_escalation": _assess_privilege_escalation,
                "field_injection": _assess_field_injection,
                "jwt_manipulation": _assess_jwt_manipulation,
                "origin_test": _assess_cors,
                "nosqli": _assess_field_injection,
                "path_traversal": _assess_field_injection,
                "open_redirect": _assess_field_injection,
                "type_confusion": _assess_field_injection,
                "boundary_value": _assess_field_injection,
                "parameter_pollution": _assess_field_injection,
            }
        )
    assessor = _violation_assessors.get(name)
    if assessor is not None:
        return assessor(baseline, experiment, diff)  # type: ignore[no-any-return]
    # Fallback generic
    from hdwp.core.oracle.violation_oracle import _assess_generic

    return _assess_generic(diff)  # type: ignore[arg-type]


def _lazy_specificity(
    name: str, diff: object, experiment: object, assessment: object
) -> float:
    """Compute specificity en lazy-loadant les calculateurs."""
    if not _specificity_computers:
        from hdwp.core.oracle.confidence import (
            _compute_behavioral_specificity_cors,
            _compute_behavioral_specificity_field_injection,
            _compute_behavioral_specificity_identity_swap,
            _compute_behavioral_specificity_jwt,
            _compute_behavioral_specificity_object_ref,
            _compute_behavioral_specificity_privilege_escalation,
        )

        _specificity_computers.update(
            {
                "identity_swap": _compute_behavioral_specificity_identity_swap,
                "object_ref_change": _compute_behavioral_specificity_object_ref,
                "privilege_escalation": _compute_behavioral_specificity_privilege_escalation,
                "field_injection": _compute_behavioral_specificity_field_injection,
                "jwt_manipulation": _compute_behavioral_specificity_jwt,
                "origin_test": _compute_behavioral_specificity_cors,
            }
        )
    computer = _specificity_computers.get(name)
    if computer is not None:
        return computer(diff, experiment, assessment)
    return 0.6 if hasattr(diff, "verdict") else 0.3


# ── Registry global ────────────────────────────────────────────────────────

_MUTATIONS: dict[str, MutationSpec] = {}


def register(
    name: str,
    owasp_category: str,
    cwe_id: str,
    remediation: str,
    assess_violation: Callable[..., ViolationAssessment] | None = None,
    compute_specificity: Callable[..., float] | None = None,
    plan_experiment: PlanFunction | None = None,
    apply_mutation: ApplyFunction | None = None,
) -> None:
    """Enregistre un type de mutation dans le registry."""
    if name in _MUTATIONS:
        log.warning("mutation.override", name=name)
    if plan_experiment is not None and not callable(plan_experiment):
        raise TypeError(f"plan_experiment must be callable, got {type(plan_experiment)}")
    if apply_mutation is not None and not callable(apply_mutation):
        raise TypeError(f"apply_mutation must be callable, got {type(apply_mutation)}")
    _MUTATIONS[name] = MutationSpec(
        name=name,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
        remediation=remediation,
        assess_violation=(
            assess_violation
            if assess_violation is not None
            else lambda b, e, d: _lazy_assess(name, b, e, d)  # type: ignore[no-any-return]
        ),
        compute_specificity=(
            compute_specificity
            if compute_specificity is not None
            else lambda mt, d, e, a: _lazy_specificity(mt, d, e, a)
        ),
        plan_experiment=plan_experiment,
        apply_mutation=apply_mutation,
    )


def get(name: str) -> MutationSpec | None:
    return _MUTATIONS.get(name)


def all_mutations() -> dict[str, MutationSpec]:
    return dict(_MUTATIONS)


def owasp_cwe(name: str) -> tuple[str, str]:
    """Retourne (owasp_category, cwe_id) pour une mutation."""
    spec = _MUTATIONS.get(name)
    if spec is not None:
        return spec.owasp_category, spec.cwe_id
    return "A01:2021", "CWE-284"


def remediation(name: str) -> str:
    """Retourne le conseil de remediation pour une mutation."""
    spec = _MUTATIONS.get(name)
    if spec is not None:
        return spec.remediation
    return "Revoir les controles d'autorisation."


def assess(name: str, baseline: object, experiment: object, diff: object) -> object:
    """Evalue une violation pour une mutation donnee."""
    spec = _MUTATIONS.get(name)
    if spec is not None:
        return spec.assess_violation(baseline, experiment, diff)
    return _lazy_assess(name, baseline, experiment, diff)


def specificity(name: str, diff: object, experiment: object, assessment: object) -> float:
    """Calcule la specificite comportementale pour une mutation."""
    spec = _MUTATIONS.get(name)
    if spec is not None:
        return spec.compute_specificity(name, diff, experiment, assessment)
    return _lazy_specificity(name, diff, experiment, assessment)


def plan(
    name: str,
    hypothesis: Hypothesis,
    spec: ExperimentSpec,
    model: ApplicationModelData,
    corpus: dict[str, list[tuple[str, NormalizedRequest]]],
) -> list[ConcreteExperimentPlan]:
    """Planifie les experiences pour une mutation donnee."""
    entry = _MUTATIONS.get(name)
    if entry is not None and entry.plan_experiment is not None:
        return entry.plan_experiment(hypothesis, spec, model, corpus)
    log.warning("mutation.no_planner", mutation_type=name)
    return []


def apply(
    name: str,
    concrete_plan: ConcreteExperimentPlan,
    session_manager: SessionManager,
) -> NormalizedRequest | None:
    """Applique une mutation a un plan d'experience."""
    entry = _MUTATIONS.get(name)
    if entry is not None and entry.apply_mutation is not None:
        return entry.apply_mutation(concrete_plan, session_manager)
    log.warning("mutation.no_applier", mutation_type=name)
    return None


# ── Enregistrement des mutations integrees ──────────────────────────────────


def _register_builtins() -> None:
    """Enregistre toutes les mutations hard-codees existantes."""
    if _MUTATIONS:
        return  # deja enregistrees

    # Metadonnees statiques : toujours enregistrees, meme si les imports echouent.
    # Les fonctions plan/apply sont chargees dynamiquement dans le bloc try ci-dessous.
    # Cela garantit que assess/specificity/remediation fonctionnent meme sans plan/apply.
    _metadata: list[dict[str, object]] = [
        {
            "name": "identity_swap",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-639",
            "remediation": (
                "Verifier l'ownership de la ressource cote serveur "
                "avant de retourner les donnees."
            ),
        },
        {
            "name": "object_ref_change",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-639",
            "remediation": (
                "Verifier l'ownership de la ressource cote serveur "
                "avant de retourner les donnees."
            ),
        },
        {
            "name": "privilege_escalation",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-284",
            "remediation": "Implementer un controle de role explicite sur cet endpoint.",
        },
        {
            "name": "field_injection",
            "owasp_category": "A03:2021",
            "cwe_id": "CWE-89",
            "remediation": "Valider et echapper toutes les entrees utilisateur cote serveur.",
        },
        {
            "name": "jwt_manipulation",
            "owasp_category": "A02:2021",
            "cwe_id": "CWE-347",
            "remediation": "Valider le token JWT avec un algorithme fixe et verifie la signature.",
        },
        {
            "name": "origin_test",
            "owasp_category": "A05:2021",
            "cwe_id": "CWE-942",
            "remediation": "Restreindre Access-Control-Allow-Origin aux domaines de confiance.",
        },
        {
            "name": "race_condition",
            "owasp_category": "A04:2021",
            "cwe_id": "CWE-362",
            "remediation": "Implementer des operations atomiques avec verrous ou transactions.",
        },
        {
            "name": "token_reuse",
            "owasp_category": "A07:2021",
            "cwe_id": "CWE-613",
            "remediation": "Invalider les tokens cote serveur au logout.",
        },
        {
            "name": "path_traversal",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-22",
            "remediation": "Valider et normaliser les chemins de fichiers. Rejeter tout '..' dans les paramètres.",
        },
        {
            "name": "nosqli",
            "owasp_category": "A03:2021",
            "cwe_id": "CWE-943",
            "remediation": "Valider les types des paramètres. Rejeter les objets JS là où une chaîne est attendue.",
        },
        {
            "name": "open_redirect",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-601",
            "remediation": "Valider les URLs de redirection contre une liste blanche de domaines autorisés.",
        },
        {
            "name": "method_override",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-284",
            "remediation": "Désactiver le support des headers X-HTTP-Method-Override ou les valider côté serveur.",
        },
        {
            "name": "http_method_fuzzing",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-284",
            "remediation": "Appliquer des contrôles d'autorisation cohérents pour chaque méthode HTTP acceptée.",
        },
        {
            "name": "type_confusion",
            "owasp_category": "A03:2021",
            "cwe_id": "CWE-843",
            "remediation": "Valider et typer strictement tous les paramètres d'entrée côté serveur.",
        },
        {
            "name": "boundary_value",
            "owasp_category": "A04:2021",
            "cwe_id": "CWE-190",
            "remediation": "Gérer les cas limites : null, valeurs négatives, dépassements d'entier, chaînes vides.",
        },
        {
            "name": "parameter_pollution",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-915",
            "remediation": "Filtrer et whitelist les paramètres acceptés, rejeter les champs inconnus.",
        },
    ]
    for meta in _metadata:
        try:
            register(**meta)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            log.warning("mutation.builtin_register_failed", name=meta.get("name"), error=str(exc))

    # Enrichissement avec plan/apply : isolation par import, chaque mutation independante.
    try:
        from hdwp.core.experiment.mutation_module import (
            apply_boundary_value,
            apply_field_injection,
            apply_http_method_fuzzing,
            apply_identity_swap,
            apply_jwt_manipulation,
            apply_method_override,
            apply_nosqli,
            apply_object_ref_change,
            apply_open_redirect,
            apply_origin_test,
            apply_parameter_pollution,
            apply_path_traversal,
            apply_privilege_escalation,
            apply_race_condition,
            apply_token_reuse,
            apply_type_confusion,
        )
        from hdwp.core.experiment.request_selector import (
            plan_field_injection,
            plan_http_method_fuzzing,
            plan_identity_swap,
            plan_jwt_manipulation,
            plan_method_override,
            plan_object_ref_change,
            plan_origin_test,
            plan_privilege_escalation,
            plan_race_condition,
            plan_token_reuse,
        )

        _plan_apply: list[tuple[str, object, object]] = [
            ("identity_swap",        plan_identity_swap,        apply_identity_swap),
            ("object_ref_change",    plan_object_ref_change,    apply_object_ref_change),
            ("privilege_escalation", plan_privilege_escalation, apply_privilege_escalation),
            ("field_injection",      plan_field_injection,      apply_field_injection),
            ("jwt_manipulation",     plan_jwt_manipulation,     apply_jwt_manipulation),
            ("origin_test",          plan_origin_test,          apply_origin_test),
            ("race_condition",       plan_race_condition,       apply_race_condition),
            ("token_reuse",          plan_token_reuse,          apply_token_reuse),
            ("method_override",      plan_method_override,      apply_method_override),
            ("path_traversal",       plan_field_injection,      apply_path_traversal),
            ("nosqli",               plan_field_injection,      apply_nosqli),
            ("open_redirect",        plan_field_injection,      apply_open_redirect),
            ("http_method_fuzzing",  plan_http_method_fuzzing,  apply_http_method_fuzzing),
            ("type_confusion",       plan_field_injection,      apply_type_confusion),
            ("boundary_value",       plan_field_injection,      apply_boundary_value),
            ("parameter_pollution",  plan_field_injection,      apply_parameter_pollution),
        ]
        for mut_name, plan_fn, apply_fn in _plan_apply:
            entry = _MUTATIONS.get(mut_name)
            if entry is not None:
                # MutationSpec n'est pas frozen : mise a jour directe
                entry.plan_experiment = plan_fn  # type: ignore[assignment]
                entry.apply_mutation = apply_fn  # type: ignore[assignment]
    except ImportError as exc:
        log.warning("mutation.builtins_plan_apply_import_failed", error=str(exc))


# Auto-enregistrement a l'import
_register_builtins()
