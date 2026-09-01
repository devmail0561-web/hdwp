# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from typer.testing import CliRunner

from hdwp.cli.main import app

runner = CliRunner()


def test_plugin_list_runs() -> None:
    result = runner.invoke(app, ["plugin", "list"])
    assert result.exit_code == 0


def test_plugin_enable_unknown() -> None:
    result = runner.invoke(app, ["plugin", "enable", "nonexistent.plugin.id"])
    assert result.exit_code != 0
    assert "introuvable" in result.output


def test_plugin_enable_no_target() -> None:
    result = runner.invoke(app, ["plugin", "enable"])
    assert result.exit_code != 0


def test_plugin_disable_runs() -> None:
    result = runner.invoke(app, ["plugin", "disable", "some.plugin"])
    assert result.exit_code == 0
    assert "désactivé" in result.output


def test_plugin_unknown_action() -> None:
    result = runner.invoke(app, ["plugin", "install"])
    assert result.exit_code != 0
