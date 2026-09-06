# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import DiffVerdict, NormalizedResponse, SemanticDiff, generate_id

VOLATILE_FIELDS = frozenset({
    "timestamp", "created_at", "updated_at", "date", "time",
    "nonce", "csrf_token", "request_id", "trace_id", "correlation_id",
    "_timestamp", "ts", "iat", "exp", "jti",
})


def compute_semantic_diff(
    baseline: NormalizedResponse,
    experiment: NormalizedResponse,
    exp_a_id: str,
    exp_b_id: str,
) -> SemanticDiff:
    """Compare two responses on behavioral semantics, not raw equality."""
    status_diff = baseline.status_code != experiment.status_code

    baseline_keys = _extract_keys(baseline.body)
    experiment_keys = _extract_keys(experiment.body)
    structural_diff = baseline_keys != experiment_keys

    leaked = sorted(experiment_keys - baseline_keys - VOLATILE_FIELDS)

    b_keys = baseline_keys - VOLATILE_FIELDS
    e_keys = experiment_keys - VOLATILE_FIELDS
    if b_keys | e_keys:
        jaccard = len(b_keys & e_keys) / len(b_keys | e_keys)
    else:
        jaccard = 1.0

    behavioral_diff = not structural_diff and _values_differ(baseline.body, experiment.body)

    if leaked:
        verdict = DiffVerdict.SIGNIFICANT
        rationale = f"Leaked fields: {leaked}"
    elif structural_diff:
        verdict = DiffVerdict.SIGNIFICANT
        rationale = f"Schema changed: baseline_keys={sorted(baseline_keys)}, experiment_keys={sorted(experiment_keys)}"
    elif status_diff:
        verdict = DiffVerdict.SIGNIFICANT
        rationale = f"Status changed: {baseline.status_code} -> {experiment.status_code}"
    elif behavioral_diff:
        verdict = DiffVerdict.AMBIGUOUS
        rationale = "Same schema, values differ — requires interpretation"
    else:
        verdict = DiffVerdict.INSIGNIFICANT
        rationale = "Responses are semantically equivalent"

    data_identity = _compute_data_identity(baseline.body, experiment.body)

    return SemanticDiff(
        id=generate_id("DIFF"),
        exp_a=exp_a_id,
        exp_b=exp_b_id,
        structural_difference=structural_diff,
        behavioral_difference=behavioral_diff,
        leaked_fields=leaked,
        status_difference=status_diff,
        body_similarity=jaccard,
        data_identity_score=data_identity,
        verdict=verdict,
        verdict_rationale=rationale,
    )


def _extract_keys(body: object) -> set[str]:
    if isinstance(body, dict):
        return set(body.keys())
    return set()


def _values_differ(body_a: object, body_b: object) -> bool:
    if not isinstance(body_a, dict) or not isinstance(body_b, dict):
        return body_a != body_b
    for k in set(body_a) & set(body_b):
        if k.lower() in VOLATILE_FIELDS:
            continue
        if body_a[k] != body_b[k]:
            return True
    return False


_IDENTITY_FIELDS = frozenset({
    "id", "user_id", "userId", "email", "username", "token",
    "sub", "owner_id", "ownerId", "account_id", "accountId",
    # Extended — modern APIs often use these
    "uuid", "uid", "profile_id", "customer_id", "client_id",
    "subject", "login", "slug", "phone", "external_id", "ref",
})


def _extract_identity_values(body: object, depth: int = 0) -> dict[str, str]:
    """Extract identity fields recursively from nested JSON structures (max depth 3).

    NOTE: This is intentionally separate from _extract_keys which is used for
    structural diff and jaccard similarity. Modifying _extract_keys would break
    those computations. This function is exclusively for _compute_data_identity.
    """
    if depth > 3 or not isinstance(body, dict):
        return {}
    result: dict[str, str] = {}
    for k, v in body.items():
        if k in _IDENTITY_FIELDS and v is not None:
            result[k] = str(v)
        elif isinstance(v, dict):
            result.update(_extract_identity_values(v, depth + 1))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            result.update(_extract_identity_values(v[0], depth + 1))
    return result


def _compute_data_identity(baseline_body: object, exp_body: object) -> float | None:
    """Compare values of identity fields between baseline and experiment.

    Uses recursive extraction to handle nested APIs (GraphQL, REST envelopes like
    {"data": {"user": {"id": 42}}}).

    Returns 1.0 if same user's data (attacker got own data → no cross-user access),
    0.0 if completely different identity values (potential IDOR confirmed),
    None if no identity fields found to compare.
    """
    b_vals = _extract_identity_values(baseline_body)
    e_vals = _extract_identity_values(exp_body)

    common = set(b_vals) & set(e_vals)
    if not common:
        return None

    matching = sum(1 for k in common if b_vals[k] == e_vals[k])
    return matching / len(common)
