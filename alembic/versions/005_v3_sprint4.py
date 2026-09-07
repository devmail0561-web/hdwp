# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""V3 Sprint 4 — attack_plans, attack_transitions

Revision ID: 005
Revises: 004
Create Date: 2026-09-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_plans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("goal_type", sa.String(), nullable=False),
        sa.Column("initial_state_json", sa.String(), nullable=False),
        sa.Column("plan_steps_json", sa.String(), nullable=False),
        sa.Column("cost", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )

    op.create_table(
        "attack_transitions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("preconditions_json", sa.String(), nullable=False),
        sa.Column("effects_json", sa.String(), nullable=False),
        sa.Column("cost", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("attack_transitions")
    op.drop_table("attack_plans")
