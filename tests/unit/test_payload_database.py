# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Test suite for PayloadDatabase (Phase 0.1 hotfix).

Tests critical integration points identified in audit:
- YAML malformed handling
- Empty payloads
- Missing plugin_id
- Singleton thread-safety
- Fallback behavior
"""
import pytest
import threading
from pathlib import Path
from hdwp.store.payload_database import PayloadDatabase, PayloadVariant


class TestPayloadDatabaseYAMLLoading:
    """Test robustness of YAML loading."""

    def test_malformed_yaml_skipped_gracefully(self, tmp_path):
        """Malformed YAML doesn't crash, logs error and continues."""
        db = PayloadDatabase()

        # Create malformed YAML
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(
            "plugin_id: test\nvariants:\n  - id: broken\n    payloads: [unclosed",
            encoding="utf-8"
        )

        db._load_from_directory(tmp_path, source="test")
        # Should not raise, should log error
        assert "test" not in db._payloads

    def test_empty_yaml_handled(self, tmp_path):
        """Empty YAML file doesn't crash."""
        db = PayloadDatabase()
        empty = tmp_path / "empty.yaml"
        empty.write_text("", encoding="utf-8")

        db._load_from_directory(tmp_path, source="test")
        assert len(db._payloads) == 0

    def test_missing_plugin_id_skipped(self, tmp_path):
        """YAML without plugin_id is skipped."""
        db = PayloadDatabase()
        no_id = tmp_path / "noid.yaml"
        no_id.write_text(
            "variants:\n  - id: test\n    payloads: [test]",
            encoding="utf-8"
        )

        db._load_from_directory(tmp_path, source="test")
        assert len(db._payloads) == 0

    def test_missing_variants_skipped(self, tmp_path):
        """YAML without variants field is skipped."""
        db = PayloadDatabase()
        no_variants = tmp_path / "novariants.yaml"
        no_variants.write_text(
            "plugin_id: test.plugin",
            encoding="utf-8"
        )

        db._load_from_directory(tmp_path, source="test")
        assert len(db._payloads) == 0

    def test_valid_yaml_loaded(self, tmp_path):
        """Valid YAML is loaded correctly."""
        db = PayloadDatabase()
        valid = tmp_path / "valid.yaml"
        valid.write_text("""
plugin_id: test.plugin
mutation_type: field_injection
payload_type: test

variants:
  - id: test_variant
    payloads:
      - "test_payload_1"
      - "test_payload_2"
    tech_stack: [test]
    confidence_boost: 0.1

keywords:
  - test
  - keyword
""", encoding="utf-8")

        db._load_from_directory(tmp_path, source="test")
        assert "test.plugin" in db._payloads
        payloads = db.get_payloads("test.plugin")
        assert len(payloads) == 1
        assert payloads[0].id == "test_variant"
        assert payloads[0].value == "test_payload_1"


class TestPayloadDatabaseAPI:
    """Test PayloadDatabase public API."""

    def test_get_payloads_returns_empty_list_not_none(self):
        """get_payloads never returns None for missing plugin."""
        db = PayloadDatabase()
        result = db.get_payloads("nonexistent.plugin")
        assert result == []  # Not None
        assert isinstance(result, list)

    def test_get_payloads_tech_stack_filtering(self, tmp_path):
        """get_payloads filters by tech_stack correctly."""
        db = PayloadDatabase()
        yaml_file = tmp_path / "techstack.yaml"
        yaml_file.write_text("""
plugin_id: test.filtering
mutation_type: field_injection
payload_type: test

variants:
  - id: mysql_variant
    payloads: ["mysql_payload"]
    tech_stack: [mysql, mariadb]
  - id: postgres_variant
    payloads: ["postgres_payload"]
    tech_stack: [postgresql]
  - id: generic_variant
    payloads: ["generic_payload"]
    tech_stack: []
""", encoding="utf-8")

        db._load_from_directory(tmp_path, source="test")

        # Filter by mysql
        mysql_payloads = db.get_payloads("test.filtering", tech_stack=["mysql"])
        assert len(mysql_payloads) == 2  # mysql_variant + generic (empty tech_stack)

        # Filter by postgresql
        pg_payloads = db.get_payloads("test.filtering", tech_stack=["postgresql"])
        assert len(pg_payloads) == 2  # postgres_variant + generic

        # No tech_stack = all variants
        all_payloads = db.get_payloads("test.filtering")
        assert len(all_payloads) == 3

    def test_get_keywords(self, tmp_path):
        """get_keywords returns correct keywords."""
        db = PayloadDatabase()
        yaml_file = tmp_path / "keywords.yaml"
        yaml_file.write_text("""
plugin_id: test.keywords
mutation_type: field_injection
payload_type: test

variants:
  - id: test
    payloads: ["test"]

keywords:
  - keyword1
  - keyword2
  - keyword3
""", encoding="utf-8")

        db._load_from_directory(tmp_path, source="test")
        keywords = db.get_keywords("test.keywords")
        assert keywords == ["keyword1", "keyword2", "keyword3"]

    def test_has_payloads(self, tmp_path):
        """has_payloads returns correct boolean."""
        db = PayloadDatabase()
        yaml_file = tmp_path / "exists.yaml"
        yaml_file.write_text("""
plugin_id: test.exists
variants:
  - id: test
    payloads: ["test"]
""", encoding="utf-8")

        db._load_from_directory(tmp_path, source="test")
        assert db.has_payloads("test.exists") is True
        assert db.has_payloads("test.nonexistent") is False


class TestPayloadDatabaseThreadSafety:
    """Test singleton thread-safety."""

    def test_singleton_thread_safe(self):
        """PayloadDatabase singleton is thread-safe."""
        instances = []

        def create_instance():
            instances.append(PayloadDatabase())

        threads = [threading.Thread(target=create_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should get same instance
        assert len(set(id(i) for i in instances)) == 1

    def test_singleton_initialization_idempotent(self):
        """Multiple __init__ calls don't reset state."""
        db1 = PayloadDatabase()
        initial_id = id(db1._payloads)

        db2 = PayloadDatabase()
        assert db2 is db1
        assert id(db2._payloads) == initial_id  # Same dict instance
