# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests pour le script runner."""
import asyncio
from pathlib import Path

import pytest

from hdwp.core.exploit.script_runner import ScriptRunner


@pytest.fixture
def runner(tmp_path):
    """Créer un ScriptRunner avec workspace temporaire."""
    return ScriptRunner(workspace_dir=tmp_path)


@pytest.fixture
def simple_py_script(tmp_path):
    """Créer un script Python simple qui affiche les env vars."""
    script = tmp_path / "test_script.py"
    script.write_text(
        """#!/usr/bin/env python3
import os
import sys

finding_id = os.getenv("HDWP_FINDING_ID", "")
target_url = os.getenv("HDWP_TARGET_URL", "")

print(f"Finding: {finding_id}")
print(f"Target: {target_url}")
sys.exit(0)
"""
    )
    return script


@pytest.fixture
def failing_script(tmp_path):
    """Script qui échoue."""
    script = tmp_path / "fail.py"
    script.write_text(
        """#!/usr/bin/env python3
import sys
print("Error message", file=sys.stderr)
sys.exit(1)
"""
    )
    return script


@pytest.fixture
def timeout_script(tmp_path):
    """Script qui timeout."""
    script = tmp_path / "timeout.py"
    script.write_text(
        """#!/usr/bin/env python3
import time
time.sleep(60)  # Plus long que MAX_EXECUTION_TIME
"""
    )
    return script


# ── Tests basiques ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_execute_simple_script(runner, simple_py_script):
    """Exécute un script simple avec succès."""
    context = {
        "finding_id": "FIND-123",
        "target_url": "http://example.com",
    }

    result = await runner.execute_script(simple_py_script, context)

    assert result.success is True
    assert result.exit_code == 0
    assert "Finding: FIND-123" in result.stdout
    assert "Target: http://example.com" in result.stdout
    assert result.elapsed_ms > 0


@pytest.mark.asyncio
async def test_execute_failing_script(runner, failing_script):
    """Gère correctement un script qui échoue."""
    context = {"finding_id": "FIND-123"}

    result = await runner.execute_script(failing_script, context)

    assert result.success is False
    assert result.exit_code == 1
    assert "Error message" in result.stderr


@pytest.mark.asyncio
async def test_script_timeout(runner, timeout_script):
    """Timeout correctement un script qui prend trop de temps."""
    context = {"finding_id": "FIND-123"}

    result = await runner.execute_script(timeout_script, context)

    assert result.success is False
    assert result.exit_code == -1
    assert "Timeout" in result.stderr or "timeout" in result.stderr.lower()


# ── Tests sécurité ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_env_vars_protection(runner, tmp_path):
    """Les HDWP_* env vars ne peuvent pas être overridés."""
    script = tmp_path / "env_test.py"
    script.write_text(
        """#!/usr/bin/env python3
import os
print(os.getenv("HDWP_FINDING_ID", ""))
"""
    )

    context = {"finding_id": "REAL-ID"}
    malicious_env = {"HDWP_FINDING_ID": "FAKE-ID"}

    result = await runner.execute_script(script, context, env_vars=malicious_env)

    # Les HDWP_* vars du context doivent primer sur env_vars
    assert "REAL-ID" in result.stdout
    assert "FAKE-ID" not in result.stdout


@pytest.mark.asyncio
async def test_reject_invalid_extension(runner, tmp_path):
    """Rejette les extensions non autorisées."""
    script = tmp_path / "evil.exe"
    script.write_text("malicious code")

    context = {"finding_id": "FIND-123"}

    result = await runner.execute_script(script, context)

    assert result.success is False
    assert "Extension non supportée" in result.stderr
    assert result.exit_code == -1


@pytest.mark.asyncio
async def test_custom_env_vars(runner, tmp_path):
    """Les env vars custom sont passées au script."""
    script = tmp_path / "custom.py"
    script.write_text(
        """#!/usr/bin/env python3
import os
print(os.getenv("CUSTOM_VAR", ""))
"""
    )

    context = {"finding_id": "FIND-123"}
    custom_env = {"CUSTOM_VAR": "custom_value"}

    result = await runner.execute_script(script, context, env_vars=custom_env)

    assert result.success is True
    assert "custom_value" in result.stdout


# ── Tests contexte finding ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_all_context_vars_injected(runner, tmp_path):
    """Toutes les variables de contexte sont injectées."""
    script = tmp_path / "context.py"
    script.write_text(
        """#!/usr/bin/env python3
import os
print(f"ID={os.getenv('HDWP_FINDING_ID')}")
print(f"URL={os.getenv('HDWP_TARGET_URL')}")
print(f"PARAM={os.getenv('HDWP_PARAM_NAME')}")
print(f"EP={os.getenv('HDWP_ENDPOINT')}")
print(f"CWE={os.getenv('HDWP_CWE_ID')}")
print(f"SEV={os.getenv('HDWP_SEVERITY')}")
"""
    )

    context = {
        "finding_id": "FIND-123",
        "target_url": "http://example.com",
        "param_name": "id",
        "endpoint": "/api/users",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
    }

    result = await runner.execute_script(script, context)

    assert "ID=FIND-123" in result.stdout
    assert "URL=http://example.com" in result.stdout
    assert "PARAM=id" in result.stdout
    assert "EP=/api/users" in result.stdout
    assert "CWE=CWE-89" in result.stdout
    assert "SEV=HIGH" in result.stdout


# ── Tests performance ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_elapsed_time_measured(runner, simple_py_script):
    """Le temps d'exécution est mesuré."""
    context = {"finding_id": "FIND-123"}

    result = await runner.execute_script(simple_py_script, context)

    assert result.elapsed_ms > 0
    assert result.elapsed_ms < 5000  # Devrait être rapide


@pytest.mark.asyncio
async def test_to_dict_serialization(runner, simple_py_script):
    """ScriptExecutionResult peut être sérialisé en dict."""
    context = {"finding_id": "FIND-123"}

    result = await runner.execute_script(simple_py_script, context)
    data = result.to_dict()

    assert isinstance(data, dict)
    assert "success" in data
    assert "stdout" in data
    assert "stderr" in data
    assert "exit_code" in data
    assert "elapsed_ms" in data
    assert isinstance(data["elapsed_ms"], int)
