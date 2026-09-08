# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import pytest

from hdwp.core.attack_graph.state import AttackState, AttackTransition, StateEffects


def _make_state(**kw) -> AttackState:
    return AttackState(**kw)


def _make_effects(**kw) -> StateEffects:
    return StateEffects(**kw)


def _make_bola_finding() -> dict:
    return {
        "id": "FND-bola1",
        "property_type": "BOLA",
        "affected_endpoints": ["/api/users/123"],
        "confidence": 0.8,
    }


def _make_sqli_finding() -> dict:
    return {
        "id": "FND-sqli1",
        "property_type": "SQL_Injection",
        "affected_endpoints": ["/api/search"],
        "confidence": 0.9,
    }


def _make_privesc_finding() -> dict:
    return {
        "id": "FND-priv1",
        "property_type": "Privilege_Escalation",
        "affected_endpoints": ["/api/admin"],
        "confidence": 0.7,
    }


# ── AttackState ──────────────────────────────────────────────────────────────


class TestAttackStateCopy:
    def test_copy_independent(self) -> None:
        original = _make_state(
            assets_readable={"a"}, credentials_held={"tok"}, privileges={"user"}
        )
        copied = original.copy()
        copied.assets_readable.add("b")
        copied.credentials_held.add("tok2")
        assert "b" not in original.assets_readable
        assert "tok2" not in original.credentials_held


class TestAttackStateSatisfies:
    def test_satisfies_when_met(self) -> None:
        state = _make_state(credentials_held={"any_authenticated", "admin"})
        assert state.satisfies({"credentials_held": {"any_authenticated"}})

    def test_not_satisfies_when_missing(self) -> None:
        state = _make_state(credentials_held=set())
        assert not state.satisfies({"credentials_held": {"any_authenticated"}})

    def test_satisfies_empty_preconditions(self) -> None:
        state = _make_state()
        assert state.satisfies({})

    def test_satisfies_knowledge_key_present(self) -> None:
        # Régression : dict knowledge ignoré si isinstance check manquant
        state = _make_state(knowledge={"db_access": "postgres", "schema": "public"})
        assert state.satisfies({"knowledge": {"db_access"}})

    def test_not_satisfies_knowledge_key_missing(self) -> None:
        state = _make_state(knowledge={})
        assert not state.satisfies({"knowledge": {"db_access"}})

    def test_not_satisfies_knowledge_partial(self) -> None:
        state = _make_state(knowledge={"db_access": "postgres"})
        assert not state.satisfies({"knowledge": {"db_access", "schema"}})


class TestAttackStateApplyEffects:
    def test_grants_readable(self) -> None:
        state = _make_state()
        effects = _make_effects(grants_readable={"/api/data"})
        new_state = state.apply_effects(effects)
        assert "/api/data" in new_state.assets_readable
        assert "/api/data" not in state.assets_readable

    def test_grants_credentials_and_privileges(self) -> None:
        state = _make_state()
        effects = _make_effects(
            grants_credentials={"admin_token"},
            grants_privileges={"elevated"},
        )
        new_state = state.apply_effects(effects)
        assert "admin_token" in new_state.credentials_held
        assert "elevated" in new_state.privileges

    def test_grants_knowledge_and_tokens(self) -> None:
        state = _make_state()
        effects = _make_effects(
            grants_knowledge={"db_type": "postgres"},
            grants_tokens={"session": "abc123"},
        )
        new_state = state.apply_effects(effects)
        assert new_state.knowledge["db_type"] == "postgres"
        assert new_state.session_tokens["session"] == "abc123"


class TestAttackStateMissingFor:
    def test_counts_missing(self) -> None:
        state = _make_state(privileges={"user"})
        count = state.missing_for({
            "privileges": {"user", "admin", "superadmin"},
            "credentials_held": {"tok"},
        })
        assert count == 3  # admin + superadmin + tok

    def test_zero_when_satisfied(self) -> None:
        state = _make_state(privileges={"elevated"}, credentials_held={"tok"})
        assert state.missing_for({"privileges": {"elevated"}, "credentials_held": {"tok"}}) == 0

    def test_missing_for_knowledge_dict(self) -> None:
        # Régression : dict knowledge retournait 0 au lieu du nombre de clés manquantes
        state = _make_state(knowledge={"db_access": "postgres"})
        count = state.missing_for({"knowledge": {"db_access", "schema", "tables"}})
        assert count == 2  # schema + tables manquants

    def test_missing_for_knowledge_all_present(self) -> None:
        state = _make_state(knowledge={"db_access": "p", "schema": "s"})
        assert state.missing_for({"knowledge": {"db_access", "schema"}}) == 0


# ── AttackTransition ─────────────────────────────────────────────────────────


class TestAttackTransitionFromFinding:
    def test_bola_finding(self) -> None:
        t = AttackTransition.from_finding(_make_bola_finding())
        assert t.finding_id == "FND-bola1"
        assert t.endpoint == "/api/users/123"
        assert "/api/users/123" in t.effects.grants_readable
        assert "any_authenticated" in t.preconditions.get("credentials_held", set())

    def test_sqli_finding(self) -> None:
        t = AttackTransition.from_finding(_make_sqli_finding())
        assert "/api/search:db" in t.effects.grants_readable
        assert t.effects.grants_knowledge.get("db_access") == "/api/search"
        assert not t.preconditions  # no auth precondition for sqli

    def test_privesc_finding(self) -> None:
        t = AttackTransition.from_finding(_make_privesc_finding())
        assert "elevated" in t.effects.grants_privileges
        assert "any_authenticated" in t.preconditions.get("credentials_held", set())

    def test_cost_from_confidence(self) -> None:
        t = AttackTransition.from_finding(_make_bola_finding())  # confidence=0.8
        assert abs(t.cost - 0.2) < 0.01

    def test_cost_minimum_floor(self) -> None:
        finding = {"id": "FND-x", "property_type": "BOLA",
                    "affected_endpoints": ["/x"], "confidence": 1.0}
        t = AttackTransition.from_finding(finding)
        assert t.cost == 0.01  # max(0.01, 1-1.0)


# ── StateEffects ─────────────────────────────────────────────────────────────


class TestStateEffectsDefaults:
    def test_all_empty(self) -> None:
        e = StateEffects()
        assert e.grants_readable == set()
        assert e.grants_writable == set()
        assert e.grants_credentials == set()
        assert e.grants_privileges == set()
        assert e.grants_knowledge == {}
        assert e.grants_tokens == {}
