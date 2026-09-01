# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from pathlib import Path

import pytest

from hdwp.core.context.loader import ContextLoader, ContextLoaderError

VALID_YAML = """\
target:
  base_url: "http://localhost:8080"
  name: "Test App"
scope:
  include:
    - "http://localhost:8080/*"
roles:
  - name: "anonymous"
  - name: "user_a"
    credentials:
      type: "bearer"
      token: "${MY_TOKEN}"
options:
  allow_write: false
  max_requests_per_minute: 30
"""

MINIMAL_YAML = """\
target:
  base_url: "http://example.com"
  name: "Minimal"
scope:
  include:
    - "http://example.com/*"
"""


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "ctx.yaml"
    p.write_text(content, encoding="utf-8")
    return p


def test_load_valid_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "secret-token-value")
    path = _write_yaml(tmp_path, VALID_YAML)

    ctx = ContextLoader.load(path)

    assert ctx.base_url == "http://localhost:8080"
    assert ctx.config.target.name == "Test App"
    assert ctx.session_id.startswith("SESSION-")
    assert len(ctx.config.roles) == 2
    assert ctx.config.options.max_requests_per_minute == 30


def test_env_var_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "resolved-value")
    path = _write_yaml(tmp_path, VALID_YAML)

    ctx = ContextLoader.load(path)

    user_a = next(r for r in ctx.config.roles if r.name == "user_a")
    assert user_a.credentials is not None
    assert user_a.credentials.token == "resolved-value"


def test_missing_env_var_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MY_TOKEN", raising=False)
    path = _write_yaml(tmp_path, VALID_YAML)

    with pytest.raises(ContextLoaderError, match="MY_TOKEN"):
        ContextLoader.load(path)


def test_missing_required_fields(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, "target:\n  base_url: 'x'\n")

    with pytest.raises(ContextLoaderError, match="Validation error"):
        ContextLoader.load(path)


def test_minimal_yaml(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, MINIMAL_YAML)

    ctx = ContextLoader.load(path)

    assert ctx.base_url == "http://example.com"
    assert ctx.config.options.allow_write is False
    assert ctx.config.options.max_requests_per_minute == 60


def test_file_not_found() -> None:
    with pytest.raises(ContextLoaderError, match="not found"):
        ContextLoader.load(Path("/nonexistent/path.yaml"))


def test_invalid_yaml(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, ":\n  - :\n    bad: [")

    with pytest.raises(ContextLoaderError, match="Invalid YAML"):
        ContextLoader.load(path)


def test_context_is_frozen(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path, MINIMAL_YAML)
    ctx = ContextLoader.load(path)

    with pytest.raises(Exception):
        ctx.base_url = "http://other.com"  # type: ignore[misc]
