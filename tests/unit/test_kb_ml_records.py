# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from pathlib import Path

import pytest

from hdwp.core.knowledge.base import KnowledgeBase


@pytest.mark.asyncio
async def test_store_and_retrieve_oracle_sample(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    emb = [0.1, 0.2, 0.3, 0.4]
    await kb.store_oracle_sample(emb, "identity_swap", "CONFIRMED", "S-001")
    records = await kb.get_oracle_training_data(only_validated=False)
    assert len(records) == 1
    assert records[0]["verdict"] == "CONFIRMED"
    assert records[0]["mutation_type"] == "identity_swap"
    assert records[0]["diff_embedding"] == pytest.approx(emb)
    await kb.close()


@pytest.mark.asyncio
async def test_only_validated_filter_excludes_unvalidated(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_oracle_sample([0.1], "sqli", "CONFIRMED", "S-001", human_validated=False)
    assert len(await kb.get_oracle_training_data(only_validated=True)) == 0
    assert len(await kb.get_oracle_training_data(only_validated=False)) == 1
    await kb.close()


@pytest.mark.asyncio
async def test_only_validated_filter_includes_validated(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_oracle_sample([0.5], "bola", "CONFIRMED", "S-001", human_validated=True)
    records = await kb.get_oracle_training_data(only_validated=True)
    assert len(records) == 1
    assert bool(records[0]["human_validated"]) is True
    await kb.close()


@pytest.mark.asyncio
async def test_multiple_oracle_samples_accumulate(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    for i in range(5):
        await kb.store_oracle_sample([float(i)], "bola", "CONFIRMED", f"S-00{i}")
    records = await kb.get_oracle_training_data(only_validated=False)
    assert len(records) == 5
    await kb.close()


@pytest.mark.asyncio
async def test_store_and_retrieve_vuln_sample(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    emb = [0.5] * 30
    labels = {"bola": 0.9, "sqli": 0.1}
    await kb.store_vuln_sample(emb, labels, "S-002")
    records = await kb.get_vuln_training_data(only_validated=False)
    assert len(records) == 1
    assert records[0]["vuln_labels"] == pytest.approx(labels)
    assert records[0]["endpoint_embedding"] == pytest.approx(emb)
    await kb.close()


@pytest.mark.asyncio
async def test_store_finding_embedding(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    emb = [0.1] * 51
    await kb.store_finding_embedding("FIND-001", emb, "bola", "S-003")
    # Vérification via upsert : re-stocker ne duplique pas
    await kb.store_finding_embedding("FIND-001", [0.2] * 51, "bola", "S-003")
    engine = await kb._get_engine()
    from sqlmodel.ext.asyncio.session import AsyncSession
    from sqlmodel import select
    from hdwp.core.knowledge.models import FindingEmbeddingRecord
    async with AsyncSession(engine, expire_on_commit=False) as session:
        result = await session.exec(select(FindingEmbeddingRecord))
        records = result.all()
    assert len(records) == 1  # pas de doublon
    await kb.close()


@pytest.mark.asyncio
async def test_existing_kb_migrates_without_error(tmp_path: Path):
    """Une KB existante (sans tables ML) est migrée transparently à la première ouverture."""
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.get_session_count()  # force l'initialisation
    # Les tables ML doivent maintenant exister
    await kb.store_oracle_sample([0.0, 1.0], "jwt_manipulation", "REFUTED", "S-003")
    records = await kb.get_oracle_training_data(only_validated=False)
    assert len(records) == 1
    await kb.close()


@pytest.mark.asyncio
async def test_oracle_refuted_sample_stored(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_oracle_sample([0.1, 0.2], "field_injection", "REFUTED", "S-004")
    records = await kb.get_oracle_training_data(only_validated=False)
    assert records[0]["verdict"] == "REFUTED"
    await kb.close()


@pytest.mark.asyncio
async def test_oracle_ambiguous_sample_stored(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_oracle_sample([0.3], "identity_swap", "AMBIGUOUS", "S-005")
    records = await kb.get_oracle_training_data(only_validated=False)
    assert records[0]["verdict"] == "AMBIGUOUS"
    await kb.close()


# ── feedback_weights_history (V4 Sprint 9) ───────────────────────────────────

@pytest.mark.asyncio
async def test_store_and_get_feedback_weights_for_target(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    data = {"weights": {"oracle_strength": 2.0}, "bias": -3.0, "n_updates": 10}
    await kb.store_feedback_weights_for_target("hash_abc", "api", data)
    result = await kb.get_feedback_weights_for_target("hash_abc")
    assert result is not None
    assert result["target_hash"] == "hash_abc"
    assert result["target_type"] == "api"
    assert result["n_updates"] == 10
    assert result["bias"] == pytest.approx(-3.0)
    assert result["weights"]["oracle_strength"] == pytest.approx(2.0)
    await kb.close()


@pytest.mark.asyncio
async def test_get_feedback_weights_for_target_missing_returns_none(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    result = await kb.get_feedback_weights_for_target("nonexistent")
    assert result is None
    await kb.close()


@pytest.mark.asyncio
async def test_store_feedback_weights_for_target_upsert(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_feedback_weights_for_target(
        "hash1", "api", {"weights": {}, "bias": -4.0, "n_updates": 5}
    )
    await kb.store_feedback_weights_for_target(
        "hash1", "api", {"weights": {}, "bias": -2.0, "n_updates": 20}
    )
    result = await kb.get_feedback_weights_for_target("hash1")
    assert result is not None
    assert result["n_updates"] == 20
    assert result["bias"] == pytest.approx(-2.0)
    await kb.close()


@pytest.mark.asyncio
async def test_list_feedback_weights_snapshots_empty(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    snaps = await kb.list_feedback_weights_snapshots()
    assert snaps == []
    await kb.close()


@pytest.mark.asyncio
async def test_list_feedback_weights_snapshots_multiple(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_feedback_weights_for_target(
        "hash_a", "api", {"weights": {}, "bias": -4.0, "n_updates": 30}
    )
    await kb.store_feedback_weights_for_target(
        "hash_b", "graphql", {"weights": {}, "bias": -3.0, "n_updates": 10}
    )
    snaps = await kb.list_feedback_weights_snapshots()
    assert len(snaps) == 2
    # Trié par n_updates DESC
    assert snaps[0]["n_updates"] >= snaps[1]["n_updates"]
    hashes = {s["target_hash"] for s in snaps}
    assert hashes == {"hash_a", "hash_b"}
    await kb.close()


@pytest.mark.asyncio
async def test_list_snapshots_contains_required_keys(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_feedback_weights_for_target(
        "h1", "cms", {"weights": {"oracle_strength": 1.5}, "bias": -4.0, "n_updates": 7}
    )
    snaps = await kb.list_feedback_weights_snapshots()
    assert len(snaps) == 1
    s = snaps[0]
    for key in ("target_hash", "target_type", "weights", "bias", "n_updates"):
        assert key in s, f"key '{key}' missing"
    assert s["target_type"] == "cms"
    assert s["weights"].get("oracle_strength") == pytest.approx(1.5)
    await kb.close()


@pytest.mark.asyncio
async def test_multiple_targets_isolated(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test.db")
    await kb.store_feedback_weights_for_target(
        "h_api", "api", {"weights": {"oracle_strength": 2.0}, "bias": -1.0, "n_updates": 15}
    )
    await kb.store_feedback_weights_for_target(
        "h_cms", "cms", {"weights": {"oracle_strength": 0.5}, "bias": -5.0, "n_updates": 8}
    )
    api_data = await kb.get_feedback_weights_for_target("h_api")
    cms_data = await kb.get_feedback_weights_for_target("h_cms")
    assert api_data["weights"]["oracle_strength"] == pytest.approx(2.0)
    assert cms_data["weights"]["oracle_strength"] == pytest.approx(0.5)
    await kb.close()
