# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_CWE_EFFECTS: dict[str, dict] = yaml.safe_load(
    (Path(__file__).parent / "cwe_effects.yaml").read_text()
)


@dataclass
class AttackState:
    assets_readable: set[str] = field(default_factory=set)
    assets_writable: set[str] = field(default_factory=set)
    credentials_held: set[str] = field(default_factory=set)
    knowledge: dict[str, Any] = field(default_factory=dict)
    privileges: set[str] = field(default_factory=set)
    session_tokens: dict[str, str] = field(default_factory=dict)

    def copy(self) -> AttackState:
        return AttackState(
            assets_readable=set(self.assets_readable),
            assets_writable=set(self.assets_writable),
            credentials_held=set(self.credentials_held),
            knowledge=dict(self.knowledge),
            privileges=set(self.privileges),
            session_tokens=dict(self.session_tokens),
        )

    def satisfies(self, preconditions: dict[str, set[str]]) -> bool:
        for key, required in preconditions.items():
            current = getattr(self, key, set())
            if isinstance(current, set):
                if not required.issubset(current):
                    return False
            elif isinstance(current, dict):
                if not required.issubset(current.keys()):
                    return False
        return True

    def apply_effects(self, effects: StateEffects) -> AttackState:
        new = self.copy()
        new.assets_readable |= effects.grants_readable
        new.assets_writable |= effects.grants_writable
        new.credentials_held |= effects.grants_credentials
        new.privileges |= effects.grants_privileges
        for k, v in effects.grants_knowledge.items():
            new.knowledge[k] = v
        for k, v in effects.grants_tokens.items():
            new.session_tokens[k] = v
        return new

    def missing_for(self, preconditions: dict[str, set[str]]) -> int:
        count = 0
        for key, required in preconditions.items():
            current = getattr(self, key, set())
            if isinstance(current, set):
                count += len(required - current)
            elif isinstance(current, dict):
                count += len(required - current.keys())
        return count


@dataclass
class StateEffects:
    grants_readable: set[str] = field(default_factory=set)
    grants_writable: set[str] = field(default_factory=set)
    grants_credentials: set[str] = field(default_factory=set)
    grants_privileges: set[str] = field(default_factory=set)
    grants_knowledge: dict[str, Any] = field(default_factory=dict)
    grants_tokens: dict[str, str] = field(default_factory=dict)


@dataclass
class AttackTransition:
    finding_id: str
    finding_type: str
    endpoint: str
    method: str = "GET"
    preconditions: dict[str, set[str]] = field(default_factory=dict)
    effects: StateEffects = field(default_factory=StateEffects)
    cost: float = 0.5

    @classmethod
    def from_finding(cls, finding_data: dict) -> AttackTransition:
        finding_id = finding_data.get("id", "")
        finding_type = finding_data.get("property_type", finding_data.get("owasp_category", ""))
        endpoints = finding_data.get("affected_endpoints", [])
        endpoint = endpoints[0] if endpoints else ""
        confidence = finding_data.get("confidence", 0.5)
        cost = max(0.01, 1.0 - confidence)
        _proof_raw = finding_data.get("proof")
        proof = _proof_raw if isinstance(_proof_raw, dict) else {}
        winning_req = proof.get("winning_request") or {}
        method = winning_req.get("method", "GET")

        effects = StateEffects()
        preconditions: dict[str, set[str]] = {}

        ft_lower = finding_type.lower()
        if "bola" in ft_lower or "idor" in ft_lower:
            effects.grants_readable.add("sensitive_data")
            effects.grants_readable.add(endpoint)
            preconditions["credentials_held"] = {"any_authenticated"}
        elif "sqli" in ft_lower or "injection" in ft_lower:
            effects.grants_readable.add("sensitive_data")
            effects.grants_readable.add(f"{endpoint}:db")
            effects.grants_knowledge["db_access"] = endpoint
        elif "xss" in ft_lower:
            effects.grants_credentials.add("victim_token")
            effects.grants_knowledge["xss_vector"] = endpoint
        elif "privesc" in ft_lower or "privilege" in ft_lower:
            effects.grants_privileges.add("elevated")
            preconditions["credentials_held"] = {"any_authenticated"}
        elif "auth" in ft_lower:
            effects.grants_credentials.add("victim_token")
            effects.grants_credentials.add("any_authenticated")
            effects.grants_privileges.add("authenticated_as_victim")
        elif "ssrf" in ft_lower:
            effects.grants_readable.add("sensitive_data")
            effects.grants_readable.add(f"{endpoint}:internal")
        else:
            cwe = finding_data.get("cwe_id", "")
            cwe_entry = _CWE_EFFECTS.get(cwe)
            if cwe_entry:
                for r in cwe_entry.get("grants_readable", []):
                    effects.grants_readable.add(r)
                for p in cwe_entry.get("grants_privileges", []):
                    effects.grants_privileges.add(p)
                for c in cwe_entry.get("grants_credentials", []):
                    effects.grants_credentials.add(c)
                if "grants_knowledge_key" in cwe_entry:
                    effects.grants_knowledge[cwe_entry["grants_knowledge_key"]] = endpoint
            else:
                effects.grants_knowledge[f"endpoint:{endpoint}"] = True

        return cls(
            finding_id=finding_id,
            finding_type=finding_type,
            endpoint=endpoint,
            method=method,
            preconditions=preconditions,
            effects=effects,
            cost=cost,
        )
