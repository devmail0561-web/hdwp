# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Integration test: HDWP detects BOLA on OWASP Juice Shop.

Target: bkimminich/juice-shop (http://localhost:3000)
Vulnerability: BOLA on GET /api/Users/{id} — any authenticated user can read any user's data
Expected: at least 1 CONFIRMED finding with owasp_category A01:2021, confidence >= 0.70
"""
from __future__ import annotations

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
    TuningConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard
from hdwp.core.experiment.engine import ExperimentEngine
from hdwp.core.experiment.rate_limiter import TokenBucket
from hdwp.core.experiment.session_manager import SessionManager
from hdwp.core.hypothesis.engine import HypothesisEngine
from hdwp.core.model.application_model import ApplicationModel
from hdwp.core.model.schemas import ObservationType, RawObservation
from hdwp.core.observation.normalizer import normalize_request, normalize_response
from hdwp.core.oracle.engine import SemanticOracle
from hdwp.core.property_engine.engine import SecurityPropertyEngine
from hdwp.plugins.core.authorization.bola import BOLAPlugin
from hdwp.plugins.core.authorization.authz import AuthZPlugin
from hdwp.plugins.registry import PluginRegistry
from hdwp.store.database import init_db
from hdwp.store.repository import Repository

pytestmark = pytest.mark.integration

_ADMIN_EMAIL = "admin@juice-sh.op"
_ADMIN_PASS = "admin123"


def _juiceshop_register_and_login(base_url: str, email: str, password: str) -> tuple[str, int]:
    """Register (if needed) and login to JuiceShop. Returns (jwt_token, user_id)."""
    with httpx.Client(base_url=base_url, follow_redirects=True) as client:
        reg = client.post("/api/Users/", json={
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1, "question": "x", "createdAt": "2024-01-01", "updatedAt": "2024-01-01"},
            "securityAnswer": "x",
        })
        user_id = reg.json().get("data", {}).get("id", 0) if reg.status_code == 201 else 0
        resp = client.post("/rest/user/login", json={"email": email, "password": password})
        token = resp.json().get("authentication", {}).get("token", "")
        if not user_id:
            # Already registered — get ID via admin or from login
            user_id = resp.json().get("authentication", {}).get("umail", {})
        return token, user_id


def _juiceshop_login(base_url: str, email: str, password: str) -> str:
    """Login to JuiceShop and return JWT token."""
    with httpx.Client(base_url=base_url) as client:
        resp = client.post("/rest/user/login", json={"email": email, "password": password})
        return resp.json().get("authentication", {}).get("token", "")


@pytest.mark.asyncio
async def test_juiceshop_bola_detected(juiceshop_url: str) -> None:
    # Get two distinct authenticated users
    jwt_admin = _juiceshop_login(juiceshop_url, _ADMIN_EMAIL, _ADMIN_PASS)
    assert jwt_admin, "Failed to get admin JWT from JuiceShop"

    # Register a second user and get their ID (needed for identity_swap baseline observation)
    user2_email = "hdwp_test_user2@test.internal"
    jwt_user2, user2_id = _juiceshop_register_and_login(juiceshop_url, user2_email, "Hdwp1234!")
    assert jwt_user2, "Failed to get user2 JWT from JuiceShop"

    # If user2_id is not set (user already registered), fetch it via admin
    if not user2_id:
        with httpx.Client(base_url=juiceshop_url) as client:
            users_resp = client.get("/api/Users", headers={"Authorization": f"Bearer {jwt_admin}"})
            for u in users_resp.json().get("data", []):
                if u.get("email") == user2_email:
                    user2_id = u["id"]
                    break

    roles = [
        RoleConfig(name="admin", credentials=CredentialConfig(type="bearer", token=jwt_admin)),
        RoleConfig(name="user2", credentials=CredentialConfig(type="bearer", token=jwt_user2)),
    ]
    # JuiceShop is a known-vulnerable lab target — 0.70 threshold is appropriate
    # for validating detection against a controlled environment.
    tuning = TuningConfig(confirmed_threshold=0.70)
    config = HDWPContextConfig(
        target=TargetConfig(base_url=juiceshop_url, name="JuiceShop"),
        scope=ScopeConfig(include=[f"{juiceshop_url}/*"]),
        roles=roles,
        options=OptionsConfig(allow_write=False, max_requests_per_minute=120),
        tuning=tuning,
    )
    context = EngineContext(config=config, base_url=juiceshop_url, session_id="INT-JS-BOLA")
    scope_guard = ScopeGuard(context)

    engine_db = await init_db("sqlite+aiosqlite://")
    repository = Repository(engine_db)
    bus = AsyncEventBus()
    app_model = ApplicationModel(bus)

    registry = PluginRegistry()
    registry.register(BOLAPlugin())
    registry.register(AuthZPlugin())
    registry.enable("core.authorization.bola")
    registry.enable("core.authorization.authz")

    SecurityPropertyEngine(bus, plugin_registry=registry)
    hyp_engine = HypothesisEngine(
        bus,
        model_accessor=app_model.snapshot,
        plugin_registry=registry,
    )
    SemanticOracle(bus, repository, tuning=tuning)

    from datetime import UTC, datetime

    # Inject ONLY own-resource observations — one per role.
    # This gives the model the parameterized path pattern AND each role's own ID value.
    # The experiment engine will then generate cross-role experiments autonomously
    # (admin→/api/Users/{user2_id}, user2→/api/Users/1) to detect the BOLA.
    # Do NOT pre-inject cross-role observations: that would exhaust the "foreign" ID
    # list and prevent the engine from generating any experiments.
    pairs = [
        ("admin", jwt_admin, "/api/Users/1"),           # admin's own data
        ("user2", jwt_user2, f"/api/Users/{user2_id}"), # user2's own data (baseline)
    ]

    with httpx.Client(base_url=juiceshop_url) as client:
        for role_name, token, path in pairs:
            url = f"{juiceshop_url}{path}"
            resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code >= 500:
                continue

            norm_req = normalize_request(
                method="GET",
                url=url,
                headers={"Authorization": f"Bearer {token}"},
            )
            norm_resp = normalize_response(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                timing_ms=30.0,
            )
            obs = RawObservation(
                timestamp=datetime.now(UTC).isoformat(),
                source="active",
                type=ObservationType.HTTP,
                request=norm_req,
                response=norm_resp,
                session_id="INT-JS-BOLA",
                tags=[f"role:{role_name}"],
            )
            await bus.emit("observation.raw", obs.model_dump(), source="integration_test")

    await bus.drain()

    # Register endpoint role mappings — both roles observed on the same parameterized path
    app_model.update_role_mapping("admin", "GET:/api/Users/{id_0}")
    app_model.update_role_mapping("user2", "GET:/api/Users/{id_0}")

    pending = hyp_engine.get_pending()
    assert len(pending) > 0, "No hypotheses generated from JuiceShop /api/Users endpoint"

    session_manager = SessionManager(roles)
    rate_limiter = TokenBucket.from_rpm(120)
    exp_engine = ExperimentEngine(
        bus=bus,
        scope_guard=scope_guard,
        session_manager=session_manager,
        rate_limiter=rate_limiter,
        model_accessor=app_model.snapshot,
        corpus_accessor=app_model.get_all_corpus,
    )

    await exp_engine.run_pending(pending)
    await bus.drain()

    findings = await repository.list_findings(status="CONFIRMED")
    await session_manager.close_all()

    bola_findings = [
        f for f in findings
        if "A01" in (f.owasp_category or "")
        or "639" in (f.cwe_id or "")
        or "284" in (f.cwe_id or "")
    ]

    assert len(bola_findings) >= 1, (
        f"BOLA not detected on JuiceShop /api/Users. "
        f"All confirmed findings: {[(f.owasp_category, f.cwe_id, f.confidence) for f in findings]}"
    )
    assert bola_findings[0].confidence >= 0.70, (
        f"Confidence too low: {bola_findings[0].confidence}"
    )
