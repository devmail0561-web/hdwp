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

if TYPE_CHECKING:
    from hdwp.core.oracle.violation_oracle import ViolationAssessment


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


# Forward reference pour eviter les imports circulaires
_violation_assessors: dict[str, Callable[..., object]] = {}
_specificity_computers: dict[str, Callable[..., float]] = {}


def _lazy_assess(name: str, baseline: object, experiment: object, diff: object) -> object:
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
            }
        )
    assessor = _violation_assessors.get(name)
    if assessor is not None:
        return assessor(baseline, experiment, diff)
    # Fallback generic
    from hdwp.core.oracle.violation_oracle import _assess_generic

    return _assess_generic(diff)


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
        return computer(diff, experiment, assessment)  # type: ignore[no-any-return]
    return 0.6 if hasattr(diff, "verdict") else 0.3


# ── Registry global ────────────────────────────────────────────────────────

_MUTATIONS: dict[str, MutationSpec] = {}


def register(
    name: str,
    owasp_category: str,
    cwe_id: str,
    remediation: str,
    assess_violation: Callable[..., object] | None = None,
    compute_specificity: Callable[..., float] | None = None,
) -> None:
    """Enregistre un type de mutation dans le registry."""
    _MUTATIONS[name] = MutationSpec(
        name=name,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
        remediation=remediation,
        assess_violation=(
            assess_violation
            if assess_violation is not None
            else lambda b, e, d: _lazy_assess(name, b, e, d)
        ),
        compute_specificity=(
            compute_specificity
            if compute_specificity is not None
            else lambda mt, d, e, a: _lazy_specificity(mt, d, e, a)
        ),
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


# ── Enregistrement des mutations integrees ──────────────────────────────────

def _register_builtins() -> None:
    """Enregistre toutes les mutations hard-codees existantes."""
    if _MUTATIONS:
        return  # deja enregistrees

    register(
        name="identity_swap",
        owasp_category="A01:2021",
        cwe_id="CWE-639",
        remediation=(
            "Verifier l'ownership de la ressource cote serveur "
            "avant de retourner les donnees."
        ),
    )
    register(
        name="object_ref_change",
        owasp_category="A01:2021",
        cwe_id="CWE-639",
        remediation=(
            "Verifier l'ownership de la ressource cote serveur "
            "avant de retourner les donnees."
        ),
    )
    register(
        name="privilege_escalation",
        owasp_category="A01:2021",
        cwe_id="CWE-284",
        remediation="Implementer un controle de role explicite sur cet endpoint.",
    )
    register(
        name="field_injection",
        owasp_category="A03:2021",
        cwe_id="CWE-89",
        remediation="Valider et echapper toutes les entrees utilisateur cote serveur.",
    )
    register(
        name="jwt_manipulation",
        owasp_category="A02:2021",
        cwe_id="CWE-347",
        remediation="Valider le token JWT avec un algorithme fixe et verifie la signature.",
    )
    register(
        name="origin_test",
        owasp_category="A05:2021",
        cwe_id="CWE-942",
        remediation="Restreindre Access-Control-Allow-Origin aux domaines de confiance.",
    )


# Auto-enregistrement a l'import
_register_builtins()
