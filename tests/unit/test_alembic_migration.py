# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_migration():
    path = Path(__file__).parent.parent.parent / "alembic" / "versions" / "001_initial_schema.py"
    spec = importlib.util.spec_from_file_location("migration_001", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def test_migration_importable() -> None:
    module = _load_migration()
    assert module is not None


def test_migration_revision() -> None:
    module = _load_migration()
    assert module.revision == "001"
    assert module.down_revision is None


def test_migration_has_upgrade_downgrade() -> None:
    module = _load_migration()
    assert callable(module.upgrade)
    assert callable(module.downgrade)


def test_alembic_ini_exists() -> None:
    ini = Path(__file__).parent.parent.parent / "alembic.ini"
    assert ini.exists(), "alembic.ini doit exister à la racine du projet"


def test_alembic_env_exists() -> None:
    env = Path(__file__).parent.parent.parent / "alembic" / "env.py"
    assert env.exists(), "alembic/env.py doit exister"
