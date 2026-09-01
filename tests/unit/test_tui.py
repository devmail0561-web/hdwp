# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for the HDWP Textual TUI using the official run_test() API."""
from __future__ import annotations

import pytest

from hdwp.tui.app import HDWPApp
from hdwp.tui.messages import EngineComplete, EngineError, FindingUpdate
from hdwp.tui.screens.target import TargetScreen
from hdwp.tui.screens.findings import FindingsScreen
from hdwp.tui.widgets import HdwpHeader


@pytest.mark.asyncio
async def test_tui_starts_with_target_screen() -> None:
    """TUI launches and shows TargetScreen by default."""
    app = HDWPApp(context_path=None)
    async with app.run_test(headless=True) as pilot:
        assert isinstance(app.screen, TargetScreen)
        assert app.query_one(HdwpHeader) is not None


@pytest.mark.asyncio
async def test_tui_auto_start_skips_target() -> None:
    """TUI with auto_start_url skips TargetScreen."""
    app = HDWPApp(auto_start_url="https://example.com")
    async with app.run_test(headless=True) as pilot:
        assert not isinstance(app.screen, TargetScreen)


@pytest.mark.asyncio
async def test_target_screen_has_url_input() -> None:
    """TargetScreen has URL input and RadioSet."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        screen = app.screen
        assert isinstance(screen, TargetScreen)
        url_input = screen.query_one("#url-input")
        assert url_input is not None
        mode_radio = screen.query_one("#mode-radio")
        assert mode_radio is not None


@pytest.mark.asyncio
async def test_target_screen_invalid_url() -> None:
    """URL without scheme shows error notification."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        screen = app.screen
        assert isinstance(screen, TargetScreen)
        await pilot.click("#url-input")
        await pilot.press("b", "a", "d")
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, TargetScreen)


@pytest.mark.asyncio
async def test_findings_screen_with_in_memory_findings() -> None:
    """FindingsScreen accepts findings in memory."""
    findings = [
        {
            "id": "FIND-test1",
            "severity": "HIGH",
            "owasp_category": "A01:2021",
            "cwe_id": "CWE-639",
            "confidence": 0.97,
            "proof": {"mutation_type": "identity_swap"},
            "remediation_hint": "Test fix",
            "affected_endpoints": ["/api/users/1"],
        }
    ]
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        app.push_screen(FindingsScreen(findings=findings))
        await pilot.pause()
        assert isinstance(app.screen, FindingsScreen)


@pytest.mark.asyncio
async def test_engine_complete_message_handled() -> None:
    """EngineComplete message is handled without crash."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        app.post_message(EngineComplete(finding_count=5))
        await pilot.pause()
        # No crash means success
        assert isinstance(app.screen, TargetScreen)


@pytest.mark.asyncio
async def test_engine_error_message_handled() -> None:
    """EngineError message is handled without crash."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        app.post_message(EngineError("Simulated error"))
        await pilot.pause()
        # No crash means success
        assert isinstance(app.screen, TargetScreen)
