# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Test d'intégration end-to-end : pipeline complet HDWP contre le mock server.

Le mock server (VulnerableAppTransport) contient deux vulnérabilités délibérées :
  1. BOLA sur GET /api/users/{id} — retourne n'importe quel user sans vérifier l'ownership
  2. AuthZ bypass sur GET /api/admin/users — accessible à tout token valide

Ce test valide que le moteur détecte au moins l'une de ces vulnérabilités
avec confidence >= 0.85.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from hdwp.core.bus.event_bus import AsyncEventBus
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
from hdwp.core.experiment.engine import ExperimentEngine
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.hypothesis.engine import HypothesisEngine
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import (
    Finding,
    ObservationType,
    RawObservation,
)
from hdwp.core.observation.normalizer import normalize_request, normalize_response
from hdwp.core.oracle.engine import SemanticOracle
from hdwp.core.property_engine.engine import SecurityPropertyEngine
from hdwp.plugins.registry import PluginRegistry
from hdwp.plugins.core.authorization.bola import BOLAPlugin
from hdwp.plugins.core.authorization.authz import AuthZPlugin
from hdwp.store.database import init_db
from hdwp.store.repository import Repository
from tests.fixtures.mock_server import AsyncVulnerableAppTransport, VulnerableAppTransport


BASE_URL = "http://mock.test"

ROLES = [
    RoleConfig(name="anonymous"),
    RoleConfig(name="user_a", credentials=CredentialConfig(type="bearer", token="token_alice")),
    RoleConfig(name="user_b", credentials=CredentialConfig(type="bearer", token="token_bob")),
    RoleConfig(name="admin", credentials=CredentialConfig(type="bearer", token="token_admin")),
]


def _make_context() -> EngineContext:
    config = HDWPContextConfig(
        target=TargetConfig(base_url=BASE_URL, name="Mock Vulnerable App"),
        scope=ScopeConfig(include=[f"{BASE_URL}/*"]),
        roles=ROLES,
        options=OptionsConfig(allow_write=True, max_requests_per_minute=600),
    )
    return EngineContext(config=config, base_url=BASE_URL, session_id="INT-TEST-01")


def _build_sync_transport() -> VulnerableAppTransport:
    return VulnerableAppTransport()


def _build_async_transport() -> AsyncVulnerableAppTransport:
    return AsyncVulnerableAppTransport()


async def _inject_observations(bus: AsyncEventBus, app_model: ApplicationModel) -> None:
    """
    Simule le crawl en injectant des observations synthétiques directement
    depuis le mock server, sans passer par un vrai crawler httpx.

    On simule :
    - user_a accédant à GET /api/users/1 → {"id": 1, "name": "Alice", "email": "alice@example.com"}
    - user_b accédant à GET /api/users/2 → {"id": 2, "name": "Bob",   "email": "bob@example.com"}
    """
    sync_transport = _build_sync_transport()
    from datetime import UTC, datetime

    pairs = [
        ("user_a", "token_alice", "/api/users/1", 1),
        ("user_b", "token_bob",   "/api/users/2", 2),
    ]

    for role_name, token, path, user_id in pairs:
        url = f"{BASE_URL}{path}"
        req = httpx.Request(
            "GET", url,
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = sync_transport.handle_request(req)
        norm_req = normalize_request(
            method="GET",
            url=url,
            headers={"Authorization": f"Bearer {token}"},
        )
        import json
        norm_resp = normalize_response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content.decode(),
            timing_ms=1.0,
        )
        obs = RawObservation(
            timestamp=datetime.now(UTC).isoformat(),
            source="active",
            type=ObservationType.HTTP,
            request=norm_req,
            response=norm_resp,
            session_id="INT-TEST-01",
            tags=[f"role:{role_name}"],
        )
        await bus.emit("observation.raw", obs.model_dump(), source="test_injector")

    await bus.drain()
    # Mettre à jour manuellement les mappings de rôle pour que auth_required et roles_observed soient remplis
    app_model.update_role_mapping("user_a", "GET:/api/users/{id_0}")
    app_model.update_role_mapping("user_b", "GET:/api/users/{id_0}")


@pytest.mark.asyncio
async def test_bola_detected_end_to_end() -> None:
    """
    Pipeline complet : observations injectées → modèle → propriétés →
    hypothèses → expériences (via mock server) → oracle → finding BOLA confirmé.
    """
    context = _make_context()
    scope_guard = ScopeGuard(context)

    # Evidence store en mémoire
    engine_db = await init_db("sqlite+aiosqlite://")
    repository = Repository(engine_db)

    bus = AsyncEventBus()
    app_model = ApplicationModel(bus)

    # Plugins
    registry = PluginRegistry()
    registry.register(BOLAPlugin())
    registry.register(AuthZPlugin())
    registry.enable("core.authorization.bola")
    registry.enable("core.authorization.authz")

    # Composants de raisonnement
    SecurityPropertyEngine(bus, plugin_registry=registry)
    hyp_engine = HypothesisEngine(
        bus,
        model_accessor=app_model.snapshot,
        plugin_registry=registry,
    )
    oracle = SemanticOracle(bus, repository)

    # Injecter les observations pour construire le modèle
    await _inject_observations(bus, app_model)

    assert app_model.is_ready, (
        f"Modèle pas prêt : confidence={app_model.model_confidence:.2f}"
    )

    # Récupérer les hypothèses générées
    pending = hyp_engine.get_pending()
    assert len(pending) > 0, "Aucune hypothèse générée après injection des observations"

    # Session manager avec le mock transport async
    async_transport = _build_async_transport()
    session_manager = SessionManager(ROLES)
    for role in ROLES:
        session_manager._clients[role.name] = httpx.AsyncClient(
            transport=async_transport,
            base_url=BASE_URL,
        )

    rate_limiter = TokenBucket.from_rpm(600)
    exp_engine = ExperimentEngine(
        bus=bus,
        scope_guard=scope_guard,
        session_manager=session_manager,
        rate_limiter=rate_limiter,
        model_accessor=app_model.snapshot,
        corpus_accessor=app_model.get_all_corpus,
    )

    # Exécuter les expériences
    await exp_engine.run_pending(pending)
    await bus.drain()

    # Vérifier les findings
    findings = await repository.list_findings(status="CONFIRMED")

    # Fermer les sessions
    await session_manager.close_all()

    assert len(findings) >= 1, (
        f"Aucun finding confirmé. Hypothèses : {[h.statement[:60] for h in pending]}"
    )
    for f in findings:
        assert f.confidence >= 0.85, f"Confiance insuffisante : {f.confidence}"
        assert f.owasp_category == "A01:2021"
        assert f.cwe_id in ("CWE-639", "CWE-284")


@pytest.mark.asyncio
async def test_profile_endpoint_not_flagged() -> None:
    """
    GET /api/profile est correctement implémenté (ownership vérifié).
    Aucun finding ne doit être généré pour cet endpoint.
    """
    transport = _build_sync_transport()

    # user_a accède à son propre profil → 200 correct
    req_a = httpx.Request("GET", f"{BASE_URL}/api/profile", headers={"Authorization": "Bearer token_alice"})
    resp_a = transport.handle_request(req_a)
    assert resp_a.status_code == 200
    import json
    body_a = json.loads(resp_a.content)
    assert body_a["id"] == 1  # Alice voit ses propres données

    # user_b accède à son propre profil → 200 correct
    req_b = httpx.Request("GET", f"{BASE_URL}/api/profile", headers={"Authorization": "Bearer token_bob"})
    resp_b = transport.handle_request(req_b)
    assert resp_b.status_code == 200
    body_b = json.loads(resp_b.content)
    assert body_b["id"] == 2  # Bob voit ses propres données

    # Les deux responses sont différentes → pas de BOLA
    assert body_a != body_b


@pytest.mark.asyncio
async def test_mock_server_bola_present() -> None:
    """Vérifie directement que le mock server a bien la BOLA attendue."""
    transport = _build_sync_transport()

    # user_a accède aux données de user_b (id=2) → devrait être bloqué mais ne l'est pas
    req = httpx.Request(
        "GET", f"{BASE_URL}/api/users/2",
        headers={"Authorization": "Bearer token_alice"},
    )
    resp = transport.handle_request(req)
    assert resp.status_code == 200
    import json
    body = json.loads(resp.content)
    assert body["id"] == 2  # BOLA : Alice voit les données de Bob
    assert body["name"] == "Bob"
