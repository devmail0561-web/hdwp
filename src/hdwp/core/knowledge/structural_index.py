# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData

logger = structlog.get_logger()


@dataclass
class StructuralSignature:
    session_id: str = ""
    method_distribution: dict[str, float] = field(default_factory=dict)
    auth_pattern: str = "none"
    avg_path_depth: float = 0.0
    param_type_distribution: dict[str, float] = field(default_factory=dict)
    tech_stack_hash: str = ""
    endpoint_count: int = 0
    role_count: int = 0

    def to_vector(self) -> list[float]:
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        vec = [self.method_distribution.get(m, 0.0) for m in methods]

        auth_map = {"none": 0.0, "bearer": 0.3, "cookie": 0.5, "basic": 0.7, "mixed": 1.0}
        vec.append(auth_map.get(self.auth_pattern, 0.0))

        vec.append(min(self.avg_path_depth / 5.0, 1.0))

        param_types = ["string", "integer", "boolean", "array", "object"]
        vec.extend(self.param_type_distribution.get(t, 0.0) for t in param_types)

        vec.append(min(self.endpoint_count / 50.0, 1.0))
        vec.append(min(self.role_count / 10.0, 1.0))

        return vec


def build_signature(
    model: ApplicationModelData, session_id: str = ""
) -> StructuralSignature:
    endpoints = model.endpoints
    params = model.parameters
    roles = model.roles
    tech_stack = model.tech_stack

    method_counts: dict[str, int] = {}
    total_methods = 0
    path_depths: list[int] = []

    for ep in endpoints:
        for m in ep.methods:
            method_counts[m] = method_counts.get(m, 0) + 1
            total_methods += 1
        depth = len([s for s in ep.path.split("/") if s])
        path_depths.append(depth)

    method_dist = {m: c / total_methods for m, c in method_counts.items()} if total_methods else {}
    avg_depth = sum(path_depths) / len(path_depths) if path_depths else 0.0

    auth_types: set[str] = set()
    for r in roles:
        auth_types.add(getattr(r, "credential_type", None) or "none")
    auth_types.discard("none")
    if len(auth_types) > 1:
        auth_pattern = "mixed"
    elif auth_types:
        auth_pattern = auth_types.pop()
    else:
        auth_pattern = "none"

    param_type_counts: dict[str, int] = {}
    total_params = len(params)
    for p in params:
        t = p.type_inferred
        param_type_counts[t] = param_type_counts.get(t, 0) + 1
    param_type_dist = {t: c / total_params for t, c in param_type_counts.items()} if total_params else {}

    import hashlib
    stack_str = ",".join(sorted(tech_stack))
    tech_hash = hashlib.md5(stack_str.encode(), usedforsecurity=False).hexdigest()[:8]

    return StructuralSignature(
        session_id=session_id,
        method_distribution=method_dist,
        auth_pattern=auth_pattern,
        avg_path_depth=avg_depth,
        param_type_distribution=param_type_dist,
        tech_stack_hash=tech_hash,
        endpoint_count=len(endpoints),
        role_count=len(roles),
    )


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class StructuralIndex:
    def __init__(self) -> None:
        self._signatures: list[StructuralSignature] = []

    def add(self, sig: StructuralSignature) -> None:
        self._signatures.append(sig)

    def find_similar(
        self, query: StructuralSignature, threshold: float = 0.8
    ) -> list[tuple[StructuralSignature, float]]:
        query_vec = query.to_vector()
        results: list[tuple[StructuralSignature, float]] = []
        for sig in self._signatures:
            if sig.session_id == query.session_id:
                continue
            sim = cosine_similarity(query_vec, sig.to_vector())
            if sim >= threshold:
                results.append((sig, sim))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    @property
    def signatures(self) -> list[StructuralSignature]:
        return list(self._signatures)
