# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""FSM helper utilities."""
from __future__ import annotations

from hdwp.core.model.schemas import ApplicationFSM


def fsm_to_dot(fsm: ApplicationFSM) -> str:
    """Render a FSM as a Graphviz DOT string (for debugging)."""
    lines = ["digraph FSM {", '  rankdir=LR;']
    for state in fsm.states:
        shape = "doublecircle" if state.id == fsm.initial_state else "circle"
        lines.append(f'  "{state.id}" [label="{state.label}", shape={shape}];')
    for t in fsm.transitions:
        label = f"{t.trigger.method} {t.trigger.url}"
        lines.append(f'  "{t.from_state}" -> "{t.to_state}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def fsm_summary(fsm: ApplicationFSM) -> str:
    """Return a one-line human-readable summary of a FSM."""
    return (
        f"FSM(id={fsm.id}, states={len(fsm.states)}, "
        f"transitions={len(fsm.transitions)}, confidence={fsm.confidence:.2f})"
    )
