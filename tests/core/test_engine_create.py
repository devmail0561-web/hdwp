# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for HDWPEngine.create_from_context."""
from __future__ import annotations

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus


@pytest.mark.asyncio
async def test_create_from_context_shares_bus() -> None:
    """create_from_context should use the provided bus instance."""
    from pathlib import Path

    from hdwp.core.context.loader import ContextLoader

    # Create a minimal context file
    import tempfile

    content = """\
target:
  base_url: "https://test.example.com"
  name: "test"
scope:
  include:
    - "https://test.example.com/*"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
        context_path = Path(f.name)

    try:
        context = ContextLoader.load(context_path)
        bus = AsyncEventBus()

        from hdwp.core.engine import HDWPEngine

        engine = await HDWPEngine.create_from_context(context, bus)
        try:
            assert engine._bus is bus
            assert engine._context.base_url == "https://test.example.com"
        finally:
            await engine.close()
    finally:
        context_path.unlink(missing_ok=True)
