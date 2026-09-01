# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Test d'intégration : découverte autonome via le vrai ActiveCrawler.

Valide que le moteur peut :
1. Crawler une page HTML avec des liens vers des endpoints REST
2. Construire le modèle applicatif depuis les observations
3. Inférer des propriétés d'autorisation depuis les endpoints découverts

Le test utilise le vrai ActiveCrawler.crawl() — pas de réimplémentation BFS.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import httpx
import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.context.config_schema import (
    CredentialConfig,
    HDWPContextConfig,
    OptionsConfig,
    RoleConfig,
    ScopeConfig,
    TargetConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import ObservationType, RawObservation
from hdwp.core.observation.active_crawler import ActiveCrawler
from hdwp.core.observation.normalizer import normalize_request, normalize_response
from hdwp.core.property_engine.engine import SecurityPropertyEngine
from tests.fixtures.mock_server import AsyncVulnerableAppTransport

BASE_URL = "http://mock.local"

ROLES = [
    RoleConfig(name="anonymous"),
    RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="token_alice")),
]


def _make_context() -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url=BASE_URL, name="Mock App"),
        scope=ScopeConfig(include=[f"{BASE_URL}/*"]),
        roles=ROLES,
        options=OptionsConfig(allow_write=False, max_requests_per_minute=6000),
    )
    return EngineContext(config=config, base_url=BASE_URL, session_id="CRAWL-TEST-01")


@pytest.mark.asyncio
async def test_crawler_discovers_api_endpoints_from_html() -> None:
    """
    Le vrai ActiveCrawler.crawl() suit les liens <a href> de la page d'accueil
    HTML et découvre les endpoints REST sans injection manuelle d'observations.
    """
    context = _make_context()
    transport = AsyncVulnerableAppTransport()
    bus = AsyncEventBus()
    app_model = ApplicationModel(bus)
    scope_guard = ScopeGuard(context)
    rate_limiter = TokenBucket.from_rpm(6000)

    crawler = ActiveCrawler(
        bus=bus,
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        roles=ROLES,
        session_id=context.session_id,
        max_depth=2,
        max_pages=20,
    )

    # Patcher httpx.AsyncClient dans le module active_crawler pour injecter
    # le transport mock — le vrai crawler code s'exécute, seule la connexion réseau
    # est interceptée.
    OriginalClient = httpx.AsyncClient

    def _patched_client(**kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return OriginalClient(transport=transport, **kwargs)  # type: ignore[arg-type]

    with patch("hdwp.core.observation.active_crawler.httpx.AsyncClient", _patched_client):
        await crawler.crawl(BASE_URL + "/")

    await bus.drain()

    snapshot = app_model.snapshot()
    paths = {ep.path for ep in snapshot.endpoints}

    assert len(paths) >= 2, f"Trop peu d'endpoints découverts via liens HTML : {paths}"
    assert any("/api/users/" in p or "/api/users/{" in p for p in paths), (
        f"Endpoint /api/users/ non découvert par le vrai crawler. Paths : {paths}"
    )


@pytest.mark.asyncio
async def test_mock_server_homepage_has_links() -> None:
    """Vérifie que la page d'accueil expose bien des liens vers les APIs."""
    transport = AsyncVulnerableAppTransport()
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "/api/users/1" in resp.text
    assert "/api/admin/users" in resp.text


@pytest.mark.asyncio
async def test_property_engine_infers_bola_from_crawled_model() -> None:
    """
    Après observations injectées, le PropertyEngine infère au moins une propriété
    d'autorisation (BOLA) depuis le modèle comportemental.
    """
    context = _make_context()
    bus = AsyncEventBus()
    app_model = ApplicationModel(bus)
    SecurityPropertyEngine(bus)

    pairs = [
        ("user_a", "token_alice", f"{BASE_URL}/api/users/1", {"id": 1, "name": "Alice"}),
        ("user_a", "token_alice", f"{BASE_URL}/api/users/2", {"id": 2, "name": "Bob"}),
    ]
    for role_name, token, url, body in pairs:
        norm_req = normalize_request("GET", url, {"Authorization": f"Bearer {token}"})
        norm_resp = normalize_response(200, {"content-type": "application/json"}, body, 5.0)
        obs = RawObservation(
            timestamp=datetime.now(UTC).isoformat(),
            source="active",
            type=ObservationType.HTTP,
            request=norm_req,
            response=norm_resp,
            session_id=context.session_id,
            tags=[f"role:{role_name}"],
        )
        await bus.emit(OBSERVATION_RAW, obs.model_dump(), source="test")

    await bus.drain()
    snapshot = app_model.snapshot()

    params_with_affects = [p for p in snapshot.parameters if p.affects_object]
    assert len(params_with_affects) >= 1, (
        f"Aucun paramètre avec affects_object détecté. "
        f"Params : {[(p.name, p.type_inferred) for p in snapshot.parameters]}"
    )
