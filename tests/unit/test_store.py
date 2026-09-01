# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import pytest

from hdwp.core.model.schemas import (
    ConfidenceScore,
    Finding,
    Hypothesis,
    HypothesisStatus,
    NormalizedRequest,
    NormalizedResponse,
    ObservationType,
    RawObservation,
)
from hdwp.store.database import init_db
from hdwp.store.repository import Repository


@pytest.fixture
async def repo():
    engine = await init_db("sqlite+aiosqlite://")
    return Repository(engine)


def _make_observation(**overrides):
    defaults = dict(
        timestamp="2026-09-01T12:00:00Z",
        source="active",
        type=ObservationType.HTTP,
        session_id="sess-001",
        request=NormalizedRequest(
            method="GET",
            url="http://localhost/api/users/1",
            headers={"Authorization": "Bearer secret-token"},
        ),
        response=NormalizedResponse(status_code=200, body={"id": 1, "name": "alice"}),
    )
    defaults.update(overrides)
    return RawObservation(**defaults)


def _make_finding(**overrides):
    defaults = dict(
        hypothesis_id="HYP-aaa",
        property_id="PROP-bbb",
        status="CONFIRMED",
        confidence=0.9,
        confidence_breakdown=ConfidenceScore(
            oracle_strength=1.0,
            reproducibility=0.9,
            observation_quality=0.8,
            behavioral_specificity=0.85,
            experiment_coverage=0.9,
            overall=0.9,
        ),
        severity="HIGH",
        owasp_category="A01:2021",
        cwe_id="CWE-639",
        affected_endpoints=["/api/users/{id}"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── Observation tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_save_and_get_observation(repo):
    obs = _make_observation()
    await repo.save_observation(obs)
    loaded = await repo.get_observation(obs.id)
    assert loaded is not None
    assert loaded.id == obs.id
    assert loaded.session_id == "sess-001"


@pytest.mark.asyncio
async def test_credential_filtering_on_save(repo):
    obs = _make_observation()
    await repo.save_observation(obs)
    loaded = await repo.get_observation(obs.id)
    assert loaded is not None
    assert loaded.request is not None
    assert loaded.request.headers.get("Authorization") == "[REDACTED]"


# ── Finding tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_save_and_get_finding(repo):
    finding = _make_finding()
    await repo.save_finding(finding)
    loaded = await repo.get_finding(finding.id)
    assert loaded is not None
    assert loaded.status == "CONFIRMED"
    assert loaded.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_list_findings_with_status_filter(repo):
    f1 = _make_finding(status="CONFIRMED")
    f2 = _make_finding(status="REFUTED")
    await repo.save_finding(f1)
    await repo.save_finding(f2)

    confirmed = await repo.list_findings(status="CONFIRMED")
    assert len(confirmed) == 1
    assert confirmed[0].id == f1.id

    all_findings = await repo.list_findings()
    assert len(all_findings) == 2


# ── Hypothesis tests ──────────────────────────────────────


@pytest.mark.asyncio
async def test_save_and_update_hypothesis(repo):
    hyp = Hypothesis(
        source_plugin="core.authorization.bola",
        property_id="PROP-ccc",
        statement="User A can access User B objects",
        priority="HIGH",
    )
    await repo.save_hypothesis(hyp)
    loaded = await repo.get_hypothesis(hyp.id)
    assert loaded is not None
    assert loaded.status == HypothesisStatus.PENDING

    await repo.update_hypothesis_status(hyp.id, "CONFIRMED", 0.92)
    updated = await repo.get_hypothesis(hyp.id)
    assert updated is not None
    assert updated.status == HypothesisStatus.CONFIRMED
    assert updated.confidence == pytest.approx(0.92)


@pytest.mark.asyncio
async def test_list_hypotheses_filter(repo):
    h1 = Hypothesis(
        source_plugin="test",
        property_id="PROP-a",
        statement="stmt1",
        status=HypothesisStatus.PENDING,
    )
    h2 = Hypothesis(
        source_plugin="test",
        property_id="PROP-b",
        statement="stmt2",
        status=HypothesisStatus.REFUTED,
    )
    await repo.save_hypothesis(h1)
    await repo.save_hypothesis(h2)

    pending = await repo.list_hypotheses(status="PENDING")
    assert len(pending) == 1
    assert pending[0].id == h1.id
