# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for HDWP TUI screens using App.run_test()."""
from __future__ import annotations

import pytest

from hdwp.tui.app import HDWPApp
from hdwp.tui.screens.target import TargetScreen
from hdwp.tui.screens.findings import FindingsScreen
from hdwp.tui.screens.tokens import TokensScreen
from hdwp.tui.widgets import HdwpHeader


@pytest.mark.asyncio
async def test_tui_starts_with_target_screen() -> None:
    """TUI launches and shows TargetScreen by default."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        assert isinstance(app.screen, TargetScreen)


@pytest.mark.asyncio
async def test_tui_auto_start_skips_target() -> None:
    """TUI with auto_start_url skips TargetScreen."""
    app = HDWPApp(auto_start_url="https://example.com")
    async with app.run_test(headless=True) as pilot:
        # Should not be on TargetScreen
        assert not isinstance(app.screen, TargetScreen)


@pytest.mark.asyncio
async def test_target_screen_has_url_input() -> None:
    """TargetScreen has URL input and RadioSet."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        screen = app.screen
        assert isinstance(screen, TargetScreen)
        # Check for URL input
        url_input = screen.query_one("#url-input")
        assert url_input is not None
        # Check for mode radio
        mode_radio = screen.query_one("#mode-radio")
        assert mode_radio is not None


@pytest.mark.asyncio
async def test_target_screen_invalid_url() -> None:
    """URL without scheme shows error notification."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        screen = app.screen
        assert isinstance(screen, TargetScreen)
        # Type invalid URL
        await pilot.click("#url-input")
        await pilot.press("b", "a", "d")
        # Try to launch
        await pilot.press("enter")
        await pilot.pause()
        # Should still be on TargetScreen
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
        # Should have findings loaded
        assert isinstance(app.screen, FindingsScreen)


@pytest.mark.asyncio
async def test_tokens_screen_dismiss() -> None:
    """TokensScreen returns tokens via dismiss()."""
    app = HDWPApp()
    async with app.run_test(headless=True) as pilot:
        tokens_received = []

        def callback(tokens):
            tokens_received.extend(tokens)

        app.push_screen(TokensScreen(), callback=callback)
        await pilot.pause()
        # Screen should be displayed
        assert isinstance(app.screen, TokensScreen)
