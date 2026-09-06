# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests pour les prédicats sémantiques des règles de chaînes."""
import pytest

from hdwp.core.chain.rules import (
    _get_mutation_type,
    _has_id_param_semantic,
    _is_sql_injection_semantic,
    rule_generic_active_chain,
)
from hdwp.core.model.schemas import ConfidenceScore, Finding


def _make_finding(
    cwe_id: str = "CWE-639",
    severity: str = "HIGH",
    owasp_category: str = "A01:2021",
    proof: dict | None = None,
) -> Finding:
    """Helper pour créer un finding de test."""
    return Finding(
        hypothesis_id="HYP-test",
        property_id="PROP-test",
        status="CONFIRMED",
        confidence=0.9,
        confidence_breakdown=ConfidenceScore(
            oracle_strength=1.0,
            reproducibility=0.9,
            observation_quality=0.8,
            behavioral_specificity=0.85,
            experiment_coverage=0.9,
            overall=0.9,
        ),
        severity=severity,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
        affected_endpoints=["/api/users/123"],
        proof=proof or {},
    )


# ── Tests prédicats sémantiques ──────────────────────────────────────────────


def test_get_mutation_type_from_proof():
    """Extrait mutation_type depuis proof."""
    finding = _make_finding(proof={"mutation_type": "object_ref_manipulation"})
    assert _get_mutation_type(finding) == "object_ref_manipulation"


def test_get_mutation_type_empty():
    """Retourne chaîne vide si absent."""
    finding = _make_finding(proof={})
    assert _get_mutation_type(finding) == ""


def test_is_sql_injection_semantic_via_cwe():
    """Détecte SQLi via CWE-89."""
    finding = _make_finding(
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        proof={"winning_request": {"url": "http://test.com", "method": "GET"}},
    )
    assert _is_sql_injection_semantic(finding) is True


def test_is_sql_injection_semantic_via_injection_mutation_type():
    """Détecte SQLi via mutation_type contenant 'injection'."""
    finding = _make_finding(
        cwe_id="CWE-999",
        owasp_category="A03:2021",
        proof={
            "winning_request": {"url": "http://test.com", "method": "GET"},
            "mutation_type": "field_injection",
        },
    )
    assert _is_sql_injection_semantic(finding) is True


def test_is_sql_injection_semantic_via_mutation_type():
    """Détecte SQLi via mutation_type contenant 'sql'."""
    finding = _make_finding(
        cwe_id="CWE-999",
        owasp_category="A03:2021",
        proof={
            "winning_request": {"url": "http://test.com", "method": "GET"},
            "mutation_type": "sql_injection_union",
        },
    )
    assert _is_sql_injection_semantic(finding) is True


def test_is_sql_injection_semantic_requires_active():
    """SQLi sémantique nécessite finding actif (winning_request)."""
    finding = _make_finding(
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        proof={},  # Pas de winning_request
    )
    assert _is_sql_injection_semantic(finding) is False


def test_has_id_param_semantic_via_parameter_name():
    """Détecte ID param via mutation_params.parameter_name."""
    finding = _make_finding(
        proof={
            "winning_request": {"url": "http://test.com", "method": "GET"},
            "experiment_spec": {"mutation_params": {"parameter_name": "user_id"}},
        }
    )
    assert _has_id_param_semantic(finding) is True


def test_has_id_param_semantic_various_patterns():
    """Détecte différents patterns de noms d'ID."""
    patterns = ["id", "userId", "user_id", "ID", "object_id", "recordId"]

    for param_name in patterns:
        finding = _make_finding(
            proof={
                "winning_request": {"url": "http://test.com", "method": "GET"},
                "experiment_spec": {"mutation_params": {"parameter_name": param_name}},
            }
        )
        assert (
            _has_id_param_semantic(finding) is True
        ), f"Pattern '{param_name}' devrait matcher"


def test_has_id_param_semantic_false():
    """Ne détecte pas ID param si nom ne matche pas."""
    finding = _make_finding(
        proof={
            "winning_request": {"url": "http://test.com", "method": "GET"},
            "experiment_spec": {"mutation_params": {"parameter_name": "username"}},
        }
    )
    # Fallback sur logique originale (qui checke winning_request params)
    # Ici on a pas de params dans winning_request, donc False
    assert _has_id_param_semantic(finding) is False


# ── Tests rule_generic_active_chain ──────────────────────────────────────────


def test_rule_generic_active_chain_basic():
    """Génère chaîne pour 2 findings HIGH actifs."""
    f1 = _make_finding(
        severity="HIGH",
        proof={"winning_request": {"url": "http://test.com/api/users", "method": "GET"}},
    )
    f2 = _make_finding(
        severity="CRITICAL",
        proof={"winning_request": {"url": "http://test.com/api/posts", "method": "GET"}},
    )

    chains = rule_generic_active_chain([f1, f2], model=None, target_url="http://test.com")

    assert len(chains) == 1
    assert chains[0].chain_type == "generic_active_chain"
    assert chains[0].executable is True
    assert len(chains[0].steps) == 2
    assert set(chains[0].precondition_finding_ids) == {f1.id, f2.id}


def test_rule_generic_active_chain_requires_2_findings():
    """Nécessite au moins 2 findings."""
    f1 = _make_finding(
        severity="HIGH",
        proof={"winning_request": {"url": "http://test.com/api/users", "method": "GET"}},
    )

    chains = rule_generic_active_chain([f1], model=None, target_url="")
    assert len(chains) == 0


def test_rule_generic_active_chain_requires_active():
    """Nécessite findings actifs (avec winning_request)."""
    f1 = _make_finding(severity="HIGH", proof={})  # Pas actif
    f2 = _make_finding(severity="HIGH", proof={})  # Pas actif

    chains = rule_generic_active_chain([f1, f2], model=None, target_url="")
    assert len(chains) == 0


def test_rule_generic_active_chain_requires_high_or_critical():
    """Nécessite severity HIGH ou CRITICAL."""
    f1 = _make_finding(
        severity="MEDIUM",
        proof={"winning_request": {"url": "http://test.com/api/users", "method": "GET"}},
    )
    f2 = _make_finding(
        severity="LOW",
        proof={"winning_request": {"url": "http://test.com/api/posts", "method": "GET"}},
    )

    chains = rule_generic_active_chain([f1, f2], model=None, target_url="")
    assert len(chains) == 0


def test_rule_generic_active_chain_skips_same_path():
    """Skip chaînes si même chemin de base."""
    f1 = _make_finding(
        severity="HIGH",
        proof={"winning_request": {"url": "http://test.com/api/users", "method": "GET"}},
    )
    f2 = _make_finding(
        severity="HIGH",
        proof={
            "winning_request": {"url": "http://test.com/api/users?limit=10", "method": "GET"}
        },
    )

    chains = rule_generic_active_chain([f1, f2], model=None, target_url="")
    assert len(chains) == 0  # Même chemin /api/users


def test_rule_generic_active_chain_max_combinations():
    """Limite le nombre de chaînes (5 sources × 3 cibles)."""
    findings = [
        _make_finding(
            severity="HIGH",
            proof={
                "winning_request": {"url": f"http://test.com/api/endpoint{i}", "method": "GET"}
            },
        )
        for i in range(20)
    ]

    chains = rule_generic_active_chain(findings, model=None, target_url="")

    # Max 5 sources * 3 cibles = 15 chaînes
    assert len(chains) <= 15
