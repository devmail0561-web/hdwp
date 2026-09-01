# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import DiffVerdict, NormalizedResponse
from hdwp.core.oracle.semantic_diff import compute_semantic_diff


def _resp(status: int = 200, body: object = None, content_type: str = "application/json") -> NormalizedResponse:
    return NormalizedResponse(status_code=status, body=body, content_type=content_type)


def test_status_difference_is_significant() -> None:
    baseline = _resp(200, {"id": 1, "name": "alice"})
    experiment = _resp(403, None)
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert diff.status_difference is True
    assert diff.verdict == DiffVerdict.SIGNIFICANT


def test_identical_responses_are_insignificant() -> None:
    body = {"id": 1, "name": "alice", "email": "a@example.com"}
    baseline = _resp(200, body)
    experiment = _resp(200, body.copy())
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert diff.verdict == DiffVerdict.INSIGNIFICANT
    assert diff.body_similarity == 1.0


def test_leaked_fields_are_significant() -> None:
    baseline = _resp(200, {"id": 1})
    experiment = _resp(200, {"id": 1, "secret_key": "abc123"})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert "secret_key" in diff.leaked_fields
    assert diff.verdict == DiffVerdict.SIGNIFICANT


def test_volatile_fields_ignored_in_comparison() -> None:
    # timestamp differs — should NOT cause AMBIGUOUS
    baseline = _resp(200, {"id": 1, "name": "alice", "timestamp": "2026-01-01T00:00:00Z"})
    experiment = _resp(200, {"id": 1, "name": "alice", "timestamp": "2026-06-01T12:00:00Z"})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert diff.verdict == DiffVerdict.INSIGNIFICANT


def test_structural_difference_is_significant() -> None:
    baseline = _resp(200, {"id": 1, "name": "alice"})
    experiment = _resp(200, {"user_id": 1, "username": "alice", "role": "admin"})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert diff.structural_difference is True
    assert diff.verdict == DiffVerdict.SIGNIFICANT


def test_same_schema_different_values_is_ambiguous() -> None:
    baseline = _resp(200, {"id": 1, "name": "alice"})
    experiment = _resp(200, {"id": 2, "name": "bob"})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert diff.behavioral_difference is True
    assert diff.verdict == DiffVerdict.AMBIGUOUS


def test_jaccard_similarity_computed() -> None:
    baseline = _resp(200, {"a": 1, "b": 2})
    experiment = _resp(200, {"a": 1, "c": 3})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    # keys intersection={a}, union={a,b,c} → jaccard=1/3
    assert abs(diff.body_similarity - 1 / 3) < 0.01


def test_volatile_fields_not_in_leaked() -> None:
    baseline = _resp(200, {"id": 1})
    experiment = _resp(200, {"id": 1, "timestamp": "2026-01-01"})
    diff = compute_semantic_diff(baseline, experiment, "EXP-a", "EXP-b")
    assert "timestamp" not in diff.leaked_fields
