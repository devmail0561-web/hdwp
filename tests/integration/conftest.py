# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import os
import time

import httpx
import pytest


def pytest_collection_modifyitems(config, items):
    if not os.getenv("HDWP_INTEGRATION_TARGETS"):
        skip = pytest.mark.skip(reason="Set HDWP_INTEGRATION_TARGETS=1 to run integration tests")
        for item in items:
            if "integration" in str(item.fspath):
                item.add_marker(skip)


DVWA_URL = os.getenv("DVWA_URL", "http://localhost:8080")
JUICESHOP_URL = os.getenv("JUICESHOP_URL", "http://localhost:3000")


def _wait_for_url(url: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=3, follow_redirects=True)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


@pytest.fixture(scope="session")
def dvwa_url():
    if not _wait_for_url(DVWA_URL):
        pytest.skip(f"DVWA not reachable at {DVWA_URL}")
    return DVWA_URL


@pytest.fixture(scope="session")
def juiceshop_url():
    if not _wait_for_url(JUICESHOP_URL):
        pytest.skip(f"JuiceShop not reachable at {JUICESHOP_URL}")
    return JUICESHOP_URL
