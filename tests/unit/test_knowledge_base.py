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
    assert p.IMPACT_WEIGHTS[PropertyType.AUTHORIZATION] == 1.5
    assert p.IMPACT_WEIGHTS[PropertyType.INTEGRITY] == 0.3
    # Non spécifié → valeur par défaut de la classe
    assert p.IMPACT_WEIGHTS[PropertyType.STATE] == HypothesisPrioritizer.IMPACT_WEIGHTS[PropertyType.STATE]
