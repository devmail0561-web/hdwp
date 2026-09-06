# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import math
import re

from hdwp.core.model.schemas import DiffVerdict, NormalizedResponse, SemanticDiff, generate_id

VOLATILE_FIELDS = frozenset({
    "timestamp", "created_at", "updated_at", "date", "time",
    "nonce", "csrf_token", "request_id", "trace_id", "correlation_id",
    "_timestamp", "ts", "iat", "exp", "jti",
})

SECURITY_HEADERS = frozenset({
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "cache-control", "set-cookie",
    "access-control-allow-origin", "permissions-policy",
})

_SENSITIVE_PATTERNS = [
    re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),  # JWT
    re.compile(r'^[0-9a-fA-F]{32,}$'),                                     # hex hash/key
    re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$'),                            # base64 token
    re.compile(r'.+@.+\..+'),                                              # email
    re.compile(r'^\d{13,16}$'),                                            # card/phone
]


def compute_semantic_diff(
    baseline: NormalizedResponse,
    experiment: NormalizedResponse,
    exp_a_id: str,
    exp_b_id: str,
    response_zscore: float | None = None,
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

    # ── Anomaly detection (unknown vulnerability indicators) ──────────────

    # 1. Response size ratio — large increase may indicate data extraction
    base_size = len(str(baseline.body)) if baseline.body is not None else 0
    exp_size = len(str(experiment.body)) if experiment.body is not None else 0
    size_ratio: float | None = exp_size / base_size if base_size > 0 else None

    if size_ratio is not None and size_ratio >= 2.0:
        if verdict == DiffVerdict.INSIGNIFICANT:
            verdict = DiffVerdict.AMBIGUOUS
            rationale = f"Response size anomaly: {size_ratio:.1f}x larger than baseline"
        elif verdict == DiffVerdict.AMBIGUOUS:
            verdict = DiffVerdict.SIGNIFICANT
            rationale = f"Response {size_ratio:.1f}x larger — potential data extraction"

    # 2. High-entropy / sensitive fields UNIQUEMENT présents dans experiment et pas dans baseline
    # Bug fix: comparer vs baseline pour éviter les faux positifs sur les APIs qui retournent
    # toujours des tokens (ex: Authorization JWT dans chaque réponse)
    base_suspicious = set(_detect_suspicious_fields(baseline.body))
    exp_suspicious = set(_detect_suspicious_fields(experiment.body))
    suspicious = sorted(exp_suspicious - base_suspicious)  # seulement les NOUVEAUX champs sensibles

    # 3. Security headers added or removed
    base_headers = dict(baseline.headers) if isinstance(baseline.headers, dict) else {}
    exp_headers = dict(experiment.headers) if isinstance(experiment.headers, dict) else {}
    sec_delta = _security_header_delta(base_headers, exp_headers)

    # Z-score behavioral anomaly: statistically unusual response size vs historical baseline
    if response_zscore is not None and abs(response_zscore) > 2.5:
        if verdict == DiffVerdict.INSIGNIFICANT:
            verdict = DiffVerdict.AMBIGUOUS
            rationale = f"Behavioral anomaly: Z-score={response_zscore:.1f} (statistically unusual response size)"
        elif verdict == DiffVerdict.AMBIGUOUS:
            verdict = DiffVerdict.SIGNIFICANT
            rationale = f"Behavioral anomaly confirmed: Z-score={response_zscore:.1f}"

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
        response_size_ratio=size_ratio,
        response_zscore=response_zscore,
        suspicious_fields=suspicious,
        security_headers_delta=sec_delta,
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


def _field_entropy(s: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum(f / n * math.log2(f / n) for f in freq.values())


def _detect_suspicious_fields(body: object, depth: int = 0) -> list[str]:
    """Find fields with high entropy or sensitive patterns — potential data leaks.

    Detects: JWT tokens, hex hashes, base64 API keys, emails, card numbers.
    Works recursively to depth 3 to cover nested JSON structures.
    """
    if depth > 3 or not isinstance(body, dict):
        return []
    suspicious: list[str] = []
    for k, v in body.items():
        if isinstance(v, str) and len(v) >= 16:
            entropy = _field_entropy(v)
            is_sensitive = entropy > 4.5 or any(p.match(v) for p in _SENSITIVE_PATTERNS)
            if is_sensitive:
                suspicious.append(k)
        elif isinstance(v, dict):
            for nested_k in _detect_suspicious_fields(v, depth + 1):
                suspicious.append(f"{k}.{nested_k}")
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            for nested_k in _detect_suspicious_fields(v[0], depth + 1):
                suspicious.append(f"{k}[].{nested_k}")
    return suspicious


def _security_header_delta(
    base_headers: dict[str, str],
    exp_headers: dict[str, str],
) -> dict[str, str]:
    """Detect security-relevant headers added or removed between baseline and experiment.

    A removed security header (e.g. Cache-Control: no-store disappears) may indicate
    the mutation triggered a different code path with weaker protections.
    """
    base_sec = {k.lower() for k in base_headers if k.lower() in SECURITY_HEADERS}
    exp_sec = {k.lower() for k in exp_headers if k.lower() in SECURITY_HEADERS}
    delta: dict[str, str] = {}
    for h in exp_sec - base_sec:
        delta[h] = "added"
    for h in base_sec - exp_sec:
        delta[h] = "removed"
    return delta


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
