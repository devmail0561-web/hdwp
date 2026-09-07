# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""V3 Sprint 3 — waf_signatures, payload_effectiveness

Revision ID: 004
Revises: 003
Create Date: 2026-09-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "waf_signatures",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("waf_type", sa.String(), nullable=False),
        sa.Column("detection_headers", sa.String(), nullable=False),
        sa.Column("bypass_strategies_json", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )

    op.create_table(
        "payload_effectiveness",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("payload_hash", sa.String(), nullable=False),
        sa.Column("mutation_type", sa.String(), nullable=False),
        sa.Column("tech_stack", sa.String(), nullable=True),
        sa.Column("signal_type", sa.String(), nullable=False),
        sa.Column("success_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("payload_effectiveness")
    op.drop_table("waf_signatures")
