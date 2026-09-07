# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Évaluateur de conditions de déclenchement pour les expériences adaptatives.

Évalue un trigger_condition dict contre un ExperimentResult brut (sans oracle)
pour décider si les follow_up_specs doivent être ajoutés à la queue.

Format des conditions :
  {"type": "body_contains",     "value": "MySQL"}
  {"type": "body_not_contains", "value": "error"}
  {"type": "timing_ms",         "operator": ">",  "value": 4000}
  {"type": "status_code",       "operator": "==", "value": 500}
  {"type": "body_length_gt",    "value": 5000}
  {"and": [condition, ...]}
  {"or":  [condition, ...]}
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ExperimentResult

_OPS = {
    ">":  lambda a, b: a > b,
    "<":  lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


def evaluate_trigger(condition: dict[str, Any] | None, result: ExperimentResult) -> bool:
    """Évalue une condition de déclenchement contre un ExperimentResult.

    Retourne False si condition est None ou si le résultat ne contient pas de réponse.
    """
    if condition is None:
        return False
    if result.response_received is None:
        return False
    return _eval(condition, result)


def _eval(condition: dict[str, Any], result: ExperimentResult) -> bool:
    resp = result.response_received

    # Composition logique
    if "and" in condition:
        return all(_eval(c, result) for c in condition["and"])
    if "or" in condition:
        return any(_eval(c, result) for c in condition["or"])

    ctype = condition.get("type", "")
    value = condition.get("value")
    operator = condition.get("operator", "==")

    if ctype == "body_contains":
        body_str = str(resp.body) if resp.body is not None else ""
        return str(value) in body_str

    if ctype == "body_not_contains":
        body_str = str(resp.body) if resp.body is not None else ""
        return str(value) not in body_str

    if ctype == "body_length_gt":
        body_str = str(resp.body) if resp.body is not None else ""
        return len(body_str) > int(value)

    if ctype == "timing_ms":
        timing = getattr(resp, "timing_ms", None)
        if timing is None:
            return False
        op_fn = _OPS.get(operator)
        if op_fn is None:
            return False
        return op_fn(float(timing), float(value))

    if ctype == "status_code":
        op_fn = _OPS.get(operator)
        if op_fn is None:
            return False
        return op_fn(resp.status_code, int(value))

    if ctype == "body_matches_any":
        # value est une liste de strings
        body_str = str(resp.body) if resp.body is not None else ""
        return any(s in body_str for s in (value or []))

    return False
