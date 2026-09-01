# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import (
    NormalizedRequest,
    NormalizedResponse,
    ObservationType,
    RawObservation,
)


def _make_obs(url: str, body: object) -> RawObservation:
    return RawObservation(
        timestamp=datetime.now(UTC).isoformat(),
        source="active",
        type=ObservationType.HTTP,
        request=NormalizedRequest(method="GET", url=url),
        response=NormalizedResponse(
            status_code=200,
            body=body,
            content_type="application/json",
        ),
        session_id="test",
        tags=["role:user_a"],
    )


def test_extracts_relative_path() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs(
        "http://api.test/api/users/1",
        {"id": 1, "profile_url": "/api/profiles/42"},
    )
    links = model._extract_links_from_body(obs)
    assert "http://api.test/api/profiles/42" in links


def test_no_link_from_non_path_string() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs("http://api.test/api/users", {"name": "Alice", "status": "active"})
    links = model._extract_links_from_body(obs)
    assert links == []


def test_no_crash_on_none_body() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs("http://api.test/api/items", None)
    obs.response.body = None  # type: ignore[assignment]
    links = model._extract_links_from_body(obs)
    assert links == []


def test_no_link_from_missing_request() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs("http://api.test/api/items", {"url": "/api/other"})
    obs.request = None  # type: ignore[assignment]
    links = model._extract_links_from_body(obs)
    assert links == []


def test_extracts_absolute_same_origin_url() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs(
        "http://api.test/api/users",
        {"next": "http://api.test/api/users?page=2"},
    )
    links = model._extract_links_from_body(obs)
    assert "http://api.test/api/users?page=2" in links


def test_does_not_extract_external_url() -> None:
    bus = AsyncEventBus()
    model = ApplicationModel(bus)
    obs = _make_obs(
        "http://api.test/api/users",
        {"external": "http://other.com/api/data"},
    )
    links = model._extract_links_from_body(obs)
    # external URL from a different origin should not be extracted
    assert "http://other.com/api/data" not in links
