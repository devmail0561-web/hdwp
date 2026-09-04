# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests pour le MutationRegistry avec les nouvelles mutations."""
import pytest

from hdwp.core import mutation_registry


def test_all_mutations_registered():
    """Toutes les mutations attendues sont enregistrées."""
    mutations = mutation_registry.all_mutations()

    expected = [
        "identity_swap",
        "object_ref_change",
        "privilege_escalation",
        "field_injection",
        "jwt_manipulation",
        "origin_test",
        "race_condition",
        "token_reuse",
    ]

    for name in expected:
        assert name in mutations, f"Mutation '{name}' non enregistrée"


def test_race_condition_mutation_metadata():
    """race_condition a les métadonnées correctes."""
    spec = mutation_registry.get("race_condition")

    assert spec is not None
    assert spec.name == "race_condition"
    assert spec.owasp_category == "A04:2021"
    assert spec.cwe_id == "CWE-362"
    assert "atomiques" in spec.remediation.lower() or "verrous" in spec.remediation.lower()


def test_token_reuse_mutation_metadata():
    """token_reuse a les métadonnées correctes."""
    spec = mutation_registry.get("token_reuse")

    assert spec is not None
    assert spec.name == "token_reuse"
    assert spec.owasp_category == "A07:2021"
    assert spec.cwe_id == "CWE-613"
    assert "invalid" in spec.remediation.lower()


def test_race_condition_has_plan_function():
    """race_condition a une fonction plan_experiment."""
    spec = mutation_registry.get("race_condition")

    assert spec is not None
    assert spec.plan_experiment is not None
    assert callable(spec.plan_experiment)


def test_token_reuse_has_plan_function():
    """token_reuse a une fonction plan_experiment."""
    spec = mutation_registry.get("token_reuse")

    assert spec is not None
    assert spec.plan_experiment is not None
    assert callable(spec.plan_experiment)


def test_race_condition_has_apply_function():
    """race_condition a une fonction apply_mutation."""
    spec = mutation_registry.get("race_condition")

    assert spec is not None
    assert spec.apply_mutation is not None
    assert callable(spec.apply_mutation)


def test_token_reuse_has_apply_function():
    """token_reuse a une fonction apply_mutation."""
    spec = mutation_registry.get("token_reuse")

    assert spec is not None
    assert spec.apply_mutation is not None
    assert callable(spec.apply_mutation)


def test_owasp_cwe_lookup():
    """owasp_cwe() retourne les bonnes catégories pour les nouvelles mutations."""
    owasp, cwe = mutation_registry.owasp_cwe("race_condition")
    assert owasp == "A04:2021"
    assert cwe == "CWE-362"

    owasp, cwe = mutation_registry.owasp_cwe("token_reuse")
    assert owasp == "A07:2021"
    assert cwe == "CWE-613"


def test_remediation_lookup():
    """remediation() retourne les bons conseils pour les nouvelles mutations."""
    remedy = mutation_registry.remediation("race_condition")
    assert "atomiques" in remedy.lower() or "verrous" in remedy.lower()

    remedy = mutation_registry.remediation("token_reuse")
    assert "invalid" in remedy.lower()
