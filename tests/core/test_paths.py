# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for hdwp.core.paths module."""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urlparse

import pytest

from hdwp.core.paths import (
    CONTEXTS_DIR,
    HDWP_HOME,
    WORKSPACES_DIR,
    build_context_from_url,
    context_path_for_url,
    evidence_db_url,
    evidence_db_url_with_fallback,
    model_path,
    reports_dir,
    workspace_dir,
)


class TestWorkspaceDir:
    def test_returns_path_under_workspaces(self) -> None:
        result = workspace_dir("SESSION-test123")
        assert result == WORKSPACES_DIR / "SESSION-test123"


class TestEvidenceDbUrl:
    def test_returns_sqlite_url(self) -> None:
        url = evidence_db_url("SESSION-test123")
        assert url.startswith("sqlite+aiosqlite:///")
        assert "SESSION-test123" in url
        assert url.endswith("/evidence.db")


class TestEvidenceDbUrlWithFallback:
    def test_uses_legacy_if_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        legacy = tmp_path / "evidence_store.db"
        legacy.write_text("legacy")
        monkeypatch.chdir(tmp_path)
        url = evidence_db_url_with_fallback("SESSION-abc")
        assert str(legacy) in url

    def test_falls_back_to_workspaces(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        url = evidence_db_url_with_fallback("SESSION-abc")
        assert "SESSION-abc" in url
        assert "evidence.db" in url


class TestReportsDir:
    def test_creates_reports_directory(self, tmp_path: Path) -> None:
        monkeypatch_path = tmp_path / "SESSION-test"
        result = reports_dir("SESSION-test")
        assert result.name == "reports"


class TestModelPath:
    def test_returns_model_json_path(self) -> None:
        result = model_path("SESSION-abc")
        assert result.name == "model.json"
        assert "SESSION-abc" in str(result)


class TestContextPathForUrl:
    def test_deterministic_hash(self) -> None:
        url = "https://example.com"
        path1 = context_path_for_url(url)
        path2 = context_path_for_url(url)
        assert path1 == path2

    def test_different_urls_different_hashes(self) -> None:
        path1 = context_path_for_url("https://example.com")
        path2 = context_path_for_url("https://other.com")
        assert path1 != path2

    def test_contains_url_hash(self) -> None:
        url = "https://example.com"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:8]
        path = context_path_for_url(url)
        assert url_hash in path.name


class TestBuildContextFromUrl:
    def test_creates_yaml_file(self) -> None:
        path = build_context_from_url("https://example.com")
        assert path.exists()
        assert path.suffix == ".yaml"

    def test_idempotent(self) -> None:
        path1 = build_context_from_url("https://example.com")
        path2 = build_context_from_url("https://example.com")
        assert path1 == path2

    def test_yaml_contains_base_url(self) -> None:
        path = build_context_from_url("https://example.com")
        content = path.read_text()
        assert "example.com" in content
        assert "base_url" in content
