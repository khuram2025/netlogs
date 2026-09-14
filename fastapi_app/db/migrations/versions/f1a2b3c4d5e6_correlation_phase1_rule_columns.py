"""Correlation Phase 1: rule version, match_mode, suppress_window

Adds columns to ``correlation_rules`` so a rule can be versioned, can declare
whether it produces discrete attack-chain records or recurring monitor
records, and can carry a per-rule suppression window.

Revision ID: f1a2b3c4d5e6
Revises: d7e9f3a4b2c1
Create Date: 2026-05-20 12:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "d7e9f3a4b2c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "correlation_rules",
        sa.Column("version", sa.Integer(), nullable=False,
                  server_default="1"),
    )
    op.add_column(
        "correlation_rules",
        sa.Column("match_mode", sa.String(length=20), nullable=False,
                  server_default="discrete"),
    )
    op.add_column(
        "correlation_rules",
        sa.Column("suppress_window", sa.Integer(), nullable=False,
                  server_default="3600"),
    )


def downgrade() -> None:
    op.drop_column("correlation_rules", "suppress_window")
    op.drop_column("correlation_rules", "match_mode")
    op.drop_column("correlation_rules", "version")
