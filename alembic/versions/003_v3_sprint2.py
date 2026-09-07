# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""V3 Sprint 2 — temporal_baselines, confidence_model_weights

Revision ID: 003
Revises: 002
Create Date: 2026-09-07
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "temporal_baselines",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("endpoint_path", sa.String(), nullable=False),
        sa.Column("p95_ms", sa.Float(), nullable=False),
        sa.Column("stddev_ms", sa.Float(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )

    op.create_table(
        "confidence_model_weights",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("dimensions_json", sa.String(), nullable=False),
        sa.Column("weights_json", sa.String(), nullable=False),
        sa.Column("bias", sa.Float(), nullable=False, server_default="-4.0"),
        sa.Column("validated_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("confidence_model_weights")
    op.drop_table("temporal_baselines")
