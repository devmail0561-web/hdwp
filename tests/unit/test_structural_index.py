# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any

import pytest

from hdwp.core.knowledge.structural_index import (
    StructuralIndex,
    StructuralSignature,
    build_signature,
    cosine_similarity,
)
from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ParameterNode,
)


@dataclass
class _FakeRole:
    name: str = "anonymous"
    credential_type: str | None = None
    observed_permissions: list[str] = dc_field(default_factory=list)


def _make_model(
    endpoints: list[EndpointNode] | None = None,
    parameters: list[ParameterNode] | None = None,
    roles: list[Any] | None = None,
    tech_stack: list[str] | None = None,
) -> ApplicationModelData:
    return ApplicationModelData(
        endpoints=endpoints or [],
        parameters=parameters or [],
        roles=roles or [],
        tech_stack=tech_stack or [],
        response_corpus={},
    )


# ── cosine_similarity ────────────────────────────────────────────────────────


def test_cosine_identical_vectors():
    vec = [1.0, 2.0, 3.0]
    assert cosine_similarity(vec, vec) == pytest.approx(1.0, abs=1e-6)


def test_cosine_orthogonal_vectors():
    a = [1.0, 0.0, 0.0]
    b = [0.0, 1.0, 0.0]
    assert cosine_similarity(a, b) == pytest.approx(0.0, abs=1e-6)


def test_cosine_zero_vector():
    a = [0.0, 0.0, 0.0]
    b = [1.0, 2.0, 3.0]
    assert cosine_similarity(a, b) == 0.0
    assert cosine_similarity(a, a) == 0.0


# ── build_signature ──────────────────────────────────────────────────────────


def test_build_signature_method_distribution():
    model = _make_model(
        endpoints=[
            EndpointNode(path="/api/users", methods=["GET", "POST"], parameters=[]),
            EndpointNode(path="/api/orders", methods=["GET"], parameters=[]),
        ]
    )
    sig = build_signature(model, session_id="s1")

    assert sig.method_distribution["GET"] == pytest.approx(2 / 3, abs=0.01)
    assert sig.method_distribution["POST"] == pytest.approx(1 / 3, abs=0.01)


def test_build_signature_auth_pattern():
    model = _make_model()
    model.roles = [_FakeRole(name="admin", credential_type="bearer")]  # type: ignore[list-item]
    sig = build_signature(model)
    assert sig.auth_pattern == "bearer"


def test_build_signature_auth_pattern_mixed():
    model = _make_model()
    model.roles = [  # type: ignore[list-item]
        _FakeRole(name="admin", credential_type="bearer"),
        _FakeRole(name="user", credential_type="cookie"),
    ]
    sig = build_signature(model)
    assert sig.auth_pattern == "mixed"


def test_build_signature_avg_path_depth():
    model = _make_model(
        endpoints=[
            EndpointNode(path="/api/users", methods=["GET"], parameters=[]),
            EndpointNode(path="/api/v1/orders/items", methods=["GET"], parameters=[]),
        ]
    )
    sig = build_signature(model)
    # /api/users → depth 2, /api/v1/orders/items → depth 4, avg = 3.0
    assert sig.avg_path_depth == pytest.approx(3.0, abs=0.01)


# ── StructuralIndex ──────────────────────────────────────────────────────────


def test_index_add_and_signatures():
    idx = StructuralIndex()
    sig = StructuralSignature(session_id="s1", endpoint_count=5)
    idx.add(sig)

    assert len(idx.signatures) == 1
    assert idx.signatures[0].session_id == "s1"


def test_find_similar_high_similarity():
    idx = StructuralIndex()

    sig_a = StructuralSignature(
        session_id="s1",
        method_distribution={"GET": 0.6, "POST": 0.4},
        auth_pattern="bearer",
        avg_path_depth=3.0,
        param_type_distribution={"string": 0.7, "integer": 0.3},
        endpoint_count=10,
        role_count=2,
    )
    sig_b = StructuralSignature(
        session_id="s2",
        method_distribution={"GET": 0.65, "POST": 0.35},
        auth_pattern="bearer",
        avg_path_depth=3.2,
        param_type_distribution={"string": 0.6, "integer": 0.4},
        endpoint_count=12,
        role_count=2,
    )

    idx.add(sig_a)
    results = idx.find_similar(sig_b, threshold=0.8)

    assert len(results) >= 1
    _, sim = results[0]
    assert sim > 0.8


def test_find_similar_low_similarity():
    idx = StructuralIndex()

    sig_a = StructuralSignature(
        session_id="s1",
        method_distribution={"GET": 1.0},
        auth_pattern="none",
        avg_path_depth=1.0,
        param_type_distribution={"string": 1.0},
        endpoint_count=2,
        role_count=0,
    )
    sig_b = StructuralSignature(
        session_id="s2",
        method_distribution={"DELETE": 1.0},
        auth_pattern="mixed",
        avg_path_depth=5.0,
        param_type_distribution={"object": 1.0},
        endpoint_count=50,
        role_count=10,
    )

    idx.add(sig_a)
    results = idx.find_similar(sig_b, threshold=0.3)

    if results:
        _, sim = results[0]
        assert sim < 0.5
    else:
        pass  # No results above threshold is also correct


def test_find_similar_skips_same_session():
    idx = StructuralIndex()

    sig = StructuralSignature(
        session_id="s1",
        method_distribution={"GET": 0.5, "POST": 0.5},
        auth_pattern="bearer",
        avg_path_depth=3.0,
        endpoint_count=10,
        role_count=2,
    )
    idx.add(sig)

    results = idx.find_similar(sig, threshold=0.0)
    assert len(results) == 0


# ── StructuralSignature ─────────────────────────────────────────────────────


def test_to_vector_consistent_length():
    sig_a = StructuralSignature(
        method_distribution={"GET": 0.5},
        auth_pattern="bearer",
        avg_path_depth=2.0,
    )
    sig_b = StructuralSignature()

    vec_a = sig_a.to_vector()
    vec_b = sig_b.to_vector()

    assert len(vec_a) == len(vec_b)
    assert len(vec_a) == 14  # 5 methods + 1 auth + 1 depth + 5 param_types + 1 ep_count + 1 role_count


def test_to_vector_identical_signatures_produce_identical_vectors():
    sig_a = StructuralSignature(
        method_distribution={"GET": 0.7, "POST": 0.3},
        auth_pattern="cookie",
        avg_path_depth=2.5,
        param_type_distribution={"string": 0.8, "integer": 0.2},
        endpoint_count=15,
        role_count=3,
    )
    sig_b = StructuralSignature(
        method_distribution={"GET": 0.7, "POST": 0.3},
        auth_pattern="cookie",
        avg_path_depth=2.5,
        param_type_distribution={"string": 0.8, "integer": 0.2},
        endpoint_count=15,
        role_count=3,
    )

    assert sig_a.to_vector() == sig_b.to_vector()
