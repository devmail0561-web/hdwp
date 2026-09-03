# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from pathlib import Path

import pytest

from hdwp.core.knowledge.base import BASE_WEIGHTS, KnowledgeBase
from hdwp.core.model.schemas import ConfidenceScore, Finding


def _make_finding(
    status: str = "CONFIRMED",
    owasp: str = "A01:2021",
    mutation_type: str = "identity_swap",
    confidence: float = 0.92,
) -> Finding:
    score = ConfidenceScore(overall=confidence)
    return Finding(
        hypothesis_id="HYP-test",
        property_id="PROP-test",
        status=status,  # type: ignore[arg-type]
        confidence=confidence,
        confidence_breakdown=score,
        owasp_category=owasp,
        cwe_id="CWE-639",
        severity="HIGH",
        affected_endpoints=["/api/users/1"],
        proof={"mutation_type": mutation_type},
    )


@pytest.fixture
def kb(tmp_path: Path) -> KnowledgeBase:
    return KnowledgeBase(db_path=tmp_path / "test_knowledge.db")


@pytest.mark.asyncio
async def test_bootstrap_returns_base_weights(kb: KnowledgeBase) -> None:
    """KB vide → poids statiques inchangés."""
    weights = await kb.get_adapted_weights()
    assert weights == BASE_WEIGHTS
    await kb.close()


@pytest.mark.asyncio
async def test_record_session_updates_stats(kb: KnowledgeBase) -> None:
    """3 findings CONFIRMED authorization/identity_swap → confirmed_count=3."""
    findings = [_make_finding() for _ in range(3)]
    await kb.record_session(findings, "S-001", "http://target.test")
    stats = await kb.get_stats()
    assert len(stats) == 1
    assert stats[0]["property_type"] == "authorization"
    assert stats[0]["mutation_type"] == "identity_swap"
    assert stats[0]["confirmed"] == 3
    await kb.close()


@pytest.mark.asyncio
async def test_adapted_weights_increase_after_confirmations(kb: KnowledgeBase) -> None:
    """5 CONFIRMED authorization → poids authorization > 1.0."""
    findings = [_make_finding(status="CONFIRMED", owasp="A01:2021") for _ in range(5)]
    await kb.record_session(findings, "S-001", "http://target.test")
    weights = await kb.get_adapted_weights()
    assert weights["authorization"] > 1.0
    await kb.close()


@pytest.mark.asyncio
async def test_adapted_weights_decrease_after_refutations(kb: KnowledgeBase) -> None:
    """5 REFUTED authorization → poids authorization < 1.0."""
    findings = [_make_finding(status="REFUTED", owasp="A01:2021") for _ in range(5)]
    await kb.record_session(findings, "S-001", "http://target.test")
    weights = await kb.get_adapted_weights()
    assert weights["authorization"] < 1.0
    await kb.close()


@pytest.mark.asyncio
async def test_weight_never_below_min(kb: KnowledgeBase) -> None:
    """100% refutations → poids toujours >= WEIGHT_MIN (0.2)."""
    findings = [_make_finding(status="REFUTED", owasp="A01:2021") for _ in range(50)]
    await kb.record_session(findings, "S-001", "http://target.test")
    weights = await kb.get_adapted_weights()
    for w in weights.values():
        assert w >= 0.2
    await kb.close()


@pytest.mark.asyncio
async def test_weight_never_above_max(kb: KnowledgeBase) -> None:
    """100% confirmations → poids toujours <= WEIGHT_MAX (2.0)."""
    findings = [_make_finding(status="CONFIRMED", owasp="A01:2021") for _ in range(50)]
    await kb.record_session(findings, "S-001", "http://target.test")
    weights = await kb.get_adapted_weights()
    for w in weights.values():
        assert w <= 2.0
    await kb.close()


@pytest.mark.asyncio
async def test_refuted_findings_tracked(kb: KnowledgeBase) -> None:
    """Finding REFUTED → refuted_count incrémenté."""
    findings = [_make_finding(status="REFUTED")]
    await kb.record_session(findings, "S-001", "http://target.test")
    stats = await kb.get_stats()
    assert stats[0]["refuted"] == 1
    assert stats[0]["confirmed"] == 0
    await kb.close()


@pytest.mark.asyncio
async def test_session_meta_recorded(kb: KnowledgeBase) -> None:
    """Après record_session → get_session_count() == 1."""
    findings = [_make_finding()]
    await kb.record_session(findings, "S-unique", "http://target.test")
    count = await kb.get_session_count()
    assert count == 1
    await kb.close()


@pytest.mark.asyncio
async def test_reset_clears_patterns(kb: KnowledgeBase) -> None:
    """Reset → get_stats() vide, session_meta conservé."""
    findings = [_make_finding()]
    await kb.record_session(findings, "S-001", "http://target.test")
    await kb.reset()
    stats = await kb.get_stats()
    assert stats == []
    # session_meta conservé
    count = await kb.get_session_count()
    assert count == 1
    await kb.close()


@pytest.mark.asyncio
async def test_mutation_type_from_proof(kb: KnowledgeBase) -> None:
    """finding.proof['mutation_type'] = 'object_ref_change' → bien utilisé."""
    f = _make_finding(mutation_type="object_ref_change")
    await kb.record_session([f], "S-001", "http://target.test")
    stats = await kb.get_stats()
    assert stats[0]["mutation_type"] == "object_ref_change"
    await kb.close()


@pytest.mark.asyncio
async def test_multiple_sessions_accumulate(kb: KnowledgeBase) -> None:
    """Plusieurs sessions accumulent les patterns correctement."""
    for i in range(3):
        findings = [_make_finding(confidence=0.9)]
        await kb.record_session(findings, f"S-{i:03d}", "http://target.test")
    count = await kb.get_session_count()
    assert count == 3
    stats = await kb.get_stats()
    assert stats[0]["confirmed"] == 3
    await kb.close()


def test_with_weights_creates_adapted_prioritizer() -> None:
    """HypothesisPrioritizer.with_weights retourne un prioritizer avec poids modifiés."""
    from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
    from hdwp.core.model.schemas import PropertyType

    weights = {"authorization": 1.5, "integrity": 0.3}
    p = HypothesisPrioritizer.with_weights(weights)
    assert p._impact_weights[PropertyType.AUTHORIZATION] == 1.5
    assert p._impact_weights[PropertyType.INTEGRITY] == 0.3
    assert p._impact_weights[PropertyType.STATE] == HypothesisPrioritizer.IMPACT_WEIGHTS[PropertyType.STATE]


# ── Adaptive learning tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_classify_target_url_only() -> None:
    from hdwp.core.knowledge.base import classify_target

    assert classify_target("https://example.com/api/v1/users") == "api"
    assert classify_target("https://example.com/v2/orders") == "api"
    assert classify_target("https://example.com/graphql") == "graphql"
    assert classify_target("https://example.com/rest/resources") == "api"
    assert classify_target("https://example.com/app") == "unknown"


@pytest.mark.asyncio
async def test_classify_target_with_model() -> None:
    from hdwp.core.knowledge.base import classify_target
    from hdwp.core.model.schemas import ApplicationModelData, EndpointNode

    model = ApplicationModelData(endpoints=[
        EndpointNode(path="/wp-admin/options.php", methods=["GET"]),
        EndpointNode(path="/wp-json/wp/v2/posts", methods=["GET"]),
    ])
    assert classify_target("https://example.com/site", model) == "cms"


@pytest.mark.asyncio
async def test_record_session_stores_target_type(kb: KnowledgeBase) -> None:
    findings = [_make_finding()]
    await kb.record_session(findings, "S-001", "https://example.com/api/v1")
    stats = await kb.get_stats()
    assert stats[0]["target_type"] == "api"
    await kb.close()


@pytest.mark.asyncio
async def test_get_adapted_weights_per_target_type(kb: KnowledgeBase) -> None:
    """Per-target weights used when enough data exists."""
    for i in range(5):
        findings = [_make_finding(status="CONFIRMED", owasp="A01:2021")]
        await kb.record_session(findings, f"S-api-{i}", "https://example.com/api/v1")
    for i in range(5):
        findings = [_make_finding(status="REFUTED", owasp="A01:2021")]
        await kb.record_session(findings, f"S-cms-{i}", "https://example.com/cms")

    api_weights = await kb.get_adapted_weights(target_type="api")
    cms_weights = await kb.get_adapted_weights(target_type="unknown")

    assert api_weights["authorization"] > cms_weights["authorization"]
    await kb.close()


@pytest.mark.asyncio
async def test_get_adapted_weights_fallback_insufficient_data(kb: KnowledgeBase) -> None:
    """Falls back to global when target_type has too few records."""
    findings = [_make_finding(status="CONFIRMED", owasp="A01:2021")]
    await kb.record_session(findings, "S-001", "https://example.com/api/v1")

    target_weights = await kb.get_adapted_weights(target_type="api")
    global_weights = await kb.get_adapted_weights()
    assert target_weights == global_weights
    await kb.close()


@pytest.mark.asyncio
async def test_get_confidence_weights_defaults(kb: KnowledgeBase) -> None:
    """Returns defaults when < 5 sessions."""
    weights = await kb.get_confidence_weights()
    assert weights == {"ep": 0.4, "role": 0.4, "bola": 0.2}
    await kb.close()


@pytest.mark.asyncio
async def test_get_confidence_weights_adapted(kb: KnowledgeBase) -> None:
    """Returns adapted weights after enough sessions with model_snapshot."""
    from hdwp.core.model.schemas import (
        ApplicationModelData,
        EndpointNode,
        ParameterNode,
        RoleNode,
    )

    for i in range(6):
        model = ApplicationModelData(
            endpoints=[EndpointNode(path=f"/api/e{j}", methods=["GET"]) for j in range(5)],
            roles=[RoleNode(name="admin"), RoleNode(name="user")],
            parameters=[
                ParameterNode(name="id", location="path", affects_object="OBJ-1"),
            ],
        )
        findings = [_make_finding(status="CONFIRMED")]
        await kb.record_session(
            findings, f"S-{i:03d}", "https://example.com/api/v1", model_snapshot=model
        )

    weights = await kb.get_confidence_weights()
    assert weights != {"ep": 0.4, "role": 0.4, "bola": 0.2}
    for v in weights.values():
        assert 0.1 <= v <= 0.7
    await kb.close()


@pytest.mark.asyncio
async def test_migrate_schema_idempotent(kb: KnowledgeBase) -> None:
    """Migration runs cleanly on a fresh DB (no-op)."""
    engine = await kb._get_engine()
    await kb._migrate_schema(engine)
    findings = [_make_finding()]
    await kb.record_session(findings, "S-001", "https://example.com/api/test")
    stats = await kb.get_stats()
    assert len(stats) == 1
    assert stats[0]["target_type"] == "api"
    await kb.close()


@pytest.mark.asyncio
async def test_get_stats_includes_target_type(kb: KnowledgeBase) -> None:
    findings = [_make_finding()]
    await kb.record_session(findings, "S-001", "https://example.com/graphql")
    stats = await kb.get_stats()
    assert "target_type" in stats[0]
    assert stats[0]["target_type"] == "graphql"
    await kb.close()


def test_authorization_adaptive_bola_confidence() -> None:
    """BOLA inference uses KB stats when available."""
    from hdwp.core.model.schemas import (
        ApplicationModelData,
        EndpointNode,
        ParameterNode,
        RoleNode,
    )
    from hdwp.core.property_engine.inference.authorization import AuthorizationInference

    model = ApplicationModelData(
        endpoints=[EndpointNode(path="/api/users/{id}", methods=["GET"], parameters=["PARAM-1"])],
        roles=[RoleNode(name="admin"), RoleNode(name="user")],
        parameters=[ParameterNode(id="PARAM-1", name="id", location="path", type_inferred="integer", affects_object="OBJ-1")],
    )

    without_stats = AuthorizationInference()
    props_no_stats = without_stats._infer_bola(model)
    assert props_no_stats[0].inference_confidence == 0.8

    with_stats = AuthorizationInference(kb_stats={
        ("authorization", "object_ref_change"): {"confirmed_rate": 0.9, "total": 10},
    })
    props_with_stats = with_stats._infer_bola(model)
    assert props_with_stats[0].inference_confidence != 0.8


def test_inference_registry_default_with_kb_stats() -> None:
    """default_with_kb_stats creates a registry with stats injected."""
    from hdwp.core.property_engine.inference_registry import InferenceRegistry

    kb_stats = {("authorization", "object_ref_change"): {"confirmed_rate": 0.8, "total": 5}}
    reg = InferenceRegistry.default_with_kb_stats(kb_stats)
    modules = reg.list_active()
    assert len(modules) == 7
