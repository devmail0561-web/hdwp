# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""V3 Sprint 1 — chain_findings (backfill), invariants table

Revision ID: 002
Revises: 001
Create Date: 2026-09-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # chain_findings: was in SQLModel models.py but missing from migration 001
    op.create_table(
        "chain_findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("chain_type", sa.String(), nullable=False),
        sa.Column("trigger_finding_ids", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )

    # V3 invariants: learned invariants from InvariantStore
    op.create_table(
        "invariants",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("endpoint_path", sa.String(), nullable=False),
        sa.Column("pattern_type", sa.String(), nullable=False),
        sa.Column("formal_statement", sa.String(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("violation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("data_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("invariants")
    op.drop_table("chain_findings")
