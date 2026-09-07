# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GoalType(str, Enum):
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"


@dataclass
class GoalDefinition:
    goal_type: GoalType
    required_state: dict[str, set[str]]
    description: str = ""

    def is_reached(self, state_dict: dict[str, set]) -> bool:
        for key, required in self.required_state.items():
            current = state_dict.get(key, set())
            if not required.issubset(current):
                return False
        return True


BUILTIN_GOALS: dict[GoalType, GoalDefinition] = {
    GoalType.ACCOUNT_TAKEOVER: GoalDefinition(
        goal_type=GoalType.ACCOUNT_TAKEOVER,
        required_state={
            "credentials_held": {"victim_token"},
            "privileges": {"authenticated_as_victim"},
        },
        description="Obtain authentication credentials of another user and impersonate them.",
    ),
    GoalType.DATA_EXFILTRATION: GoalDefinition(
        goal_type=GoalType.DATA_EXFILTRATION,
        required_state={
            "assets_readable": {"sensitive_data"},
        },
        description="Read sensitive data that should not be accessible to the attacker.",
    ),
    GoalType.PRIVILEGE_ESCALATION: GoalDefinition(
        goal_type=GoalType.PRIVILEGE_ESCALATION,
        required_state={
            "privileges": {"elevated"},
        },
        description="Elevate privileges from a low-privilege role to admin or higher.",
    ),
}
