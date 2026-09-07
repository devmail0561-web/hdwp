# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""V3 Sprint 5 — structural_patterns, evidence_graph

Revision ID: 006
Revises: 005
Create Date: 2026-09-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "structural_patterns",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("signature_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )

    op.create_table(
        "evidence_graph",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("from_finding_id", sa.String(), nullable=False),
        sa.Column("to_finding_id", sa.String(), nullable=False),
        sa.Column("relation_type", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("evidence_graph")
    op.drop_table("structural_patterns")
