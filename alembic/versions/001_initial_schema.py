# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Initial schema — HDWP Engine v0.1.0

Revision ID: 001
Revises:
Create Date: 2026-09-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "observations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "properties",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("inference_confidence", sa.Float(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("property_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("priority", sa.String(), nullable=False),
        sa.Column("source_plugin", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
    )
    op.create_table(
        "experiments",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hypothesis_id", sa.String(), nullable=False),
        sa.Column("timing_ms", sa.Float(), nullable=True),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "diffs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("exp_a", sa.String(), nullable=False),
        sa.Column("exp_b", sa.String(), nullable=False),
        sa.Column("verdict", sa.String(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hypothesis_id", sa.String(), nullable=False),
        sa.Column("property_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("owasp_category", sa.String(), nullable=True),
        sa.Column("cwe_id", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "model_snapshots",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("data_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    for table in [
        "model_snapshots", "findings", "diffs", "experiments",
        "hypotheses", "properties", "observations",
    ]:
        op.drop_table(table)
