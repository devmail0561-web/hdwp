# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Test suite for Phase 3 exploit strategy discovery.

Verifies:
- All 26 new strategy YAML files are discovered by StrategyRegistry
- Each strategy has required fields (id, vuln_type, ≥1 phase)
- _CWE_FAMILY covers all new Phase 3 vuln_types
- _infer_vuln_type routes Phase 3 mutation types correctly
"""
import pytest

from hdwp.core.exploit.strategy_registry import StrategyRegistry
from hdwp.server.routes.exploit import _CWE_FAMILY, _IMPACT_DESCRIPTIONS, _BASE_SCENARIOS, _infer_vuln_type

PHASE3_VULN_TYPES = {
    # Injection (11)
    "ssti", "xxe", "deserialization", "crlf", "ldap", "xpath",
    "el_injection", "prototype_pollution", "graphql", "anomaly", "django_debug",
    # Authorization (5)
    "csrf", "bfla", "laravel_mass_assign", "method_override", "authz_escalation",
    # Business Invariant (1 + 1 conditionnel)
    "race_condition", "business_boundary",
    # Configuration (3)
    "cache_poisoning", "http_smuggling", "spring_actuator",
    # File + Info + HPP (3)
    "file_upload", "hpp", "info_disclosure",
    # Session + Temporal (2)
    "session_fixation", "session_replay",
}

PHASE3_CWE_MAPPINGS = {
    "CWE-94": "ssti",
    "CWE-502": "deserialization",
    "CWE-200": "info_disclosure",  # CWE-200 partagé — graphql routé via mutation_type pre-check
    "CWE-362": "race_condition",
    "CWE-613": "session_replay",
    "CWE-843": "anomaly",
    "CWE-352": "csrf",
    "CWE-285": "bfla",
    "CWE-345": "cache_poisoning",
    "CWE-444": "http_smuggling",
    "CWE-434": "file_upload",
    "CWE-235": "hpp",
    "CWE-497": "info_disclosure",
    "CWE-611": "xxe",
    "CWE-113": "crlf",
    "CWE-90": "ldap",
    "CWE-643": "xpath",
    "CWE-917": "el_injection",
    "CWE-1321": "prototype_pollution",
    "CWE-384": "session_fixation",
    "CWE-215": "django_debug",
}


@pytest.fixture(scope="module")
def registry() -> StrategyRegistry:
    r = StrategyRegistry()
    r.discover()
    return r


class TestPhase3StrategyDiscovery:
    def test_all_phase3_vuln_types_discovered(self, registry: StrategyRegistry):
        loaded = {s.vuln_type for s in registry.list_all()}
        missing = PHASE3_VULN_TYPES - loaded
        assert not missing, f"Missing Phase 3 vuln_types: {missing}"

    def test_total_strategy_count_at_least_39(self, registry: StrategyRegistry):
        total = len(registry.list_all())
        assert total >= 39, f"Expected ≥ 39 strategies (14 existants + 25 phase3), got {total}"

    def test_each_phase3_strategy_has_required_fields(self, registry: StrategyRegistry):
        for strat in registry.list_all():
            if strat.vuln_type not in PHASE3_VULN_TYPES:
                continue
            assert strat.id, f"Strategy {strat.vuln_type} has no id"
            assert strat.vuln_type, f"Strategy {strat.id} has no vuln_type"
            assert strat.phases, f"Strategy {strat.id} has no phases"

    def test_each_phase3_strategy_id_is_unique(self, registry: StrategyRegistry):
        ids = [s.id for s in registry.list_all()]
        assert len(ids) == len(set(ids)), "Duplicate strategy IDs detected"

    def test_each_phase3_strategy_has_at_least_one_phase(self, registry: StrategyRegistry):
        for strat in registry.list_all():
            if strat.vuln_type not in PHASE3_VULN_TYPES:
                continue
            assert len(strat.phases) >= 1, f"Strategy {strat.id} has 0 phases"

    def test_phase3_strategies_are_enabled_by_default(self, registry: StrategyRegistry):
        for strat in registry.list_all():
            if strat.vuln_type not in PHASE3_VULN_TYPES:
                continue
            enabled = {s.id for s in registry.list_enabled()}
            assert strat.id in enabled, f"Strategy {strat.id} is not enabled by default"


class TestPhase3CWEFamily:
    def test_all_phase3_cwe_mappings_present(self):
        for cwe, expected_vuln_type in PHASE3_CWE_MAPPINGS.items():
            assert cwe in _CWE_FAMILY, f"CWE {cwe} missing from _CWE_FAMILY"
            assert _CWE_FAMILY[cwe] == expected_vuln_type, (
                f"_CWE_FAMILY[{cwe}] = {_CWE_FAMILY[cwe]!r}, expected {expected_vuln_type!r}"
            )

    def test_existing_cwe_mappings_untouched(self):
        pre_existing = {
            "CWE-639": "bola", "CWE-89": "sqli", "CWE-78": "cmdi",
            "CWE-79": "xss", "CWE-347": "jwt", "CWE-284": "privesc",
            "CWE-942": "cors", "CWE-918": "ssrf", "CWE-22": "lfi",
            "CWE-943": "nosqli", "CWE-601": "redirect", "CWE-840": "boundary",
            "CWE-915": "mass_assign",
        }
        for cwe, vuln_type in pre_existing.items():
            assert _CWE_FAMILY.get(cwe) == vuln_type, (
                f"Pre-existing CWE {cwe} broken: {_CWE_FAMILY.get(cwe)!r} != {vuln_type!r}"
            )


class TestPhase3InferVulnType:
    def test_ssti_evaluation_mutation(self):
        assert _infer_vuln_type({}, "CWE-94") == "ssti"

    def test_deserialization_mutation(self):
        assert _infer_vuln_type({}, "CWE-502") == "deserialization"

    def test_graphql_mutation(self):
        # graphql_schema_query est intercepté avant le lookup CWE (CWE-200 partagé avec info_disclosure)
        assert _infer_vuln_type({"mutation_type": "graphql_schema_query"}, "CWE-200") == "graphql"

    def test_cwe_200_routes_to_info_disclosure_without_graphql_mutation(self):
        # CWE-200 seul (pas de mutation graphql) → info_disclosure, pas graphql
        assert _infer_vuln_type({}, "CWE-200") == "info_disclosure"

    def test_race_condition_mutation(self):
        assert _infer_vuln_type({}, "CWE-362") == "race_condition"

    def test_session_replay_mutation(self):
        assert _infer_vuln_type({}, "CWE-613") == "session_replay"

    def test_anomaly_mutation_type_confusion(self):
        assert _infer_vuln_type({}, "CWE-843") == "anomaly"

    def test_mutation_type_fallback_ssti(self):
        proof = {"mutation_type": "ssti_evaluation"}
        assert _infer_vuln_type(proof) == "ssti"

    def test_mutation_type_fallback_race_condition(self):
        proof = {"mutation_type": "race_condition"}
        assert _infer_vuln_type(proof) == "race_condition"

    def test_mutation_type_fallback_token_reuse(self):
        proof = {"mutation_type": "token_reuse"}
        assert _infer_vuln_type(proof) == "session_replay"

    def test_mutation_type_fallback_type_confusion(self):
        proof = {"mutation_type": "type_confusion"}
        assert _infer_vuln_type(proof) == "anomaly"

    def test_existing_routing_untouched_sqli(self):
        assert _infer_vuln_type({"mutation_type": "field_injection"}) == "sqli"

    def test_existing_routing_untouched_bola(self):
        assert _infer_vuln_type({"mutation_type": "object_ref_change"}) == "bola"

    def test_existing_routing_untouched_jwt(self):
        assert _infer_vuln_type({"mutation_type": "jwt_manipulation"}) == "jwt"

    def test_existing_routing_untouched_cors(self):
        assert _infer_vuln_type({"mutation_type": "origin_test"}) == "cors"

    def test_cwe_takes_priority_over_mutation_type(self):
        # CWE routing should win over mutation_type heuristic
        proof = {"mutation_type": "field_injection"}
        assert _infer_vuln_type(proof, "CWE-94") == "ssti"


class TestPhase3ImpactDescriptions:
    def test_all_phase3_vuln_types_have_impact_description(self):
        for vuln_type in PHASE3_VULN_TYPES:
            assert vuln_type in _IMPACT_DESCRIPTIONS, (
                f"Missing _IMPACT_DESCRIPTIONS entry for {vuln_type}"
            )

    def test_all_phase3_vuln_types_have_base_scenarios(self):
        for vuln_type in PHASE3_VULN_TYPES:
            assert vuln_type in _BASE_SCENARIOS, (
                f"Missing _BASE_SCENARIOS entry for {vuln_type}"
            )
            assert len(_BASE_SCENARIOS[vuln_type]) >= 1, (
                f"Empty _BASE_SCENARIOS for {vuln_type}"
            )
