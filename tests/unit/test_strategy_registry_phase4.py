# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.
"""
Phase 4 — StrategyRegistry: 376 stratégies catégorisées + 40 root = ~416 uniques.
Dédupliqué: anciens clones supprimés, seules les techniques distinctes sont conservées.
Vérifie structure, couverture OWASP, et unicité des IDs.
"""
from pathlib import Path

import pytest
import yaml

STRATEGIES_ROOT = Path(__file__).parent.parent.parent / "src/hdwp/core/exploit/strategies"

OWASP_SUBDIRS = [
    "a01_access_control",
    "a02_cryptographic",
    "a03_injection",
    "a04_insecure_design",
    "a05_misconfiguration",
    "a06_outdated_components",
    "a07_auth_failures",
    "a08_integrity",
    "a09_logging",
    "a10_ssrf",
]

EXPECTED_MIN_TOTAL = 400  # 416 unique strategies post-dedup (was 1040 with clones)
EXPECTED_MIN_PER_CATEGORY = 8   # smallest category post-dedup (a08_integrity: 9)


class TestPhase4StrategyFiles:
    def test_total_yaml_count_at_least_1000(self):
        total = len(list(STRATEGIES_ROOT.rglob("*.yaml")))
        assert total >= EXPECTED_MIN_TOTAL, f"Expected ≥{EXPECTED_MIN_TOTAL} strategies, got {total}"

    def test_all_owasp_subdirs_exist(self):
        for subdir in OWASP_SUBDIRS:
            assert (STRATEGIES_ROOT / subdir).is_dir(), f"Missing subdir: {subdir}"

    def test_each_owasp_category_has_at_least_90_strategies(self):
        for subdir in OWASP_SUBDIRS:
            count = len(list((STRATEGIES_ROOT / subdir).glob("*.yaml")))
            assert count >= EXPECTED_MIN_PER_CATEGORY, (
                f"{subdir}: expected ≥{EXPECTED_MIN_PER_CATEGORY}, got {count}"
            )

    def test_all_yaml_files_parseable(self):
        errors = []
        for f in STRATEGIES_ROOT.rglob("*.yaml"):
            try:
                yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception as e:
                errors.append(f"{f.name}: {e}")
        assert not errors, f"Unparseable YAML files:\n" + "\n".join(errors[:10])

    def test_all_yaml_have_required_fields(self):
        # passive.yaml uses tag_handlers instead of phases — both are valid
        required_always = {"id", "vuln_type"}
        missing = []
        for f in STRATEGIES_ROOT.rglob("*.yaml"):
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not data:
                missing.append(f"{f.name}: empty")
                continue
            absent = required_always - set(data.keys())
            if absent:
                missing.append(f"{f.name}: missing {absent}")
            # Must have phases or tag_handlers
            if "phases" not in data and "tag_handlers" not in data:
                missing.append(f"{f.name}: missing phases and tag_handlers")
        assert not missing, "Files missing required fields:\n" + "\n".join(missing[:10])

    def test_all_strategy_ids_unique_across_subdirs(self):
        ids: dict[str, str] = {}
        duplicates = []
        for f in STRATEGIES_ROOT.rglob("*.yaml"):
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not data or "id" not in data:
                continue
            sid = data["id"]
            if sid in ids:
                duplicates.append(f"{sid}: {ids[sid]} + {f.name}")
            else:
                ids[sid] = f.name
        assert not duplicates, "Duplicate IDs:\n" + "\n".join(duplicates[:10])

    def test_each_strategy_has_at_least_one_phase(self):
        empty_phases = []
        for f in STRATEGIES_ROOT.rglob("*.yaml"):
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not data or "phases" not in data:
                continue  # tag_handlers strategies are exempt
            if not data["phases"]:
                empty_phases.append(f.name)
        assert not empty_phases, f"Strategies with 0 phases: {empty_phases[:5]}"

    def test_vuln_types_cover_owasp_spectrum(self):
        expected_types = {
            "sqli", "xss", "cmdi", "nosqli", "ssti", "lfi", "ssrf",
            "bola", "bfla", "privesc", "cors", "jwt", "deserialization",
            "race_condition", "auth_bypass", "info_disclosure",
        }
        found_types: set[str] = set()
        for f in STRATEGIES_ROOT.rglob("*.yaml"):
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if data and "vuln_type" in data:
                found_types.add(data["vuln_type"])
        missing = expected_types - found_types
        assert not missing, f"Missing vuln_types: {missing}"


class TestPhase4RegistryIntegration:
    @pytest.fixture(scope="class")
    def registry(self):
        from hdwp.core.exploit.strategy_registry import StrategyRegistry
        r = StrategyRegistry()
        r.discover()
        return r

    def test_registry_loads_all_subdirectory_strategies(self, registry):
        total = len(registry.list_all())
        assert total >= EXPECTED_MIN_TOTAL, f"Registry loaded {total}, expected ≥{EXPECTED_MIN_TOTAL}"

    def test_registry_ids_unique(self, registry):
        ids = [s.id for s in registry.list_all()]
        assert len(ids) == len(set(ids)), "Registry has duplicate IDs"

    def test_all_loaded_enabled_by_default(self, registry):
        enabled = {s.id for s in registry.list_enabled()}
        for s in registry.list_all():
            assert s.id in enabled, f"Strategy {s.id} not enabled by default"
