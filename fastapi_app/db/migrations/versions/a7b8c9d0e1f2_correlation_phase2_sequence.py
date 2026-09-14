"""Correlation Phase 2: ordering, join_keys, schema_version

Adds columns to ``correlation_rules`` for the true sequence engine:

  ordering        — 'sequence' (stage N must follow stage N-1 in event time)
                    or 'any_order' (legacy: independent trailing windows)
  join_keys       — JSON list of columns that link stages into one chain
                    (e.g. ["srcip"] or ["srcip","dstip"]); NULL falls back to
                    stage 1's group_by
  schema_version  — stage-JSON shape marker (2 = Phase 2)

``ordering`` defaults to 'sequence': for the seeded multi-stage "then" rules
that is the intended semantics, and for single-stage rules it is a no-op.

Revision ID: a7b8c9d0e1f2
Revises: f1a2b3c4d5e6
Create Date: 2026-05-20 13:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "correlation_rules",
        sa.Column("ordering", sa.String(length=20), nullable=False,
                  server_default="sequence"),
    )
    op.add_column(
        "correlation_rules",
        sa.Column("schema_version", sa.Integer(), nullable=False,
                  server_default="2"),
    )
    op.add_column(
        "correlation_rules",
        sa.Column("join_keys", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("correlation_rules", "join_keys")
    op.drop_column("correlation_rules", "schema_version")
    op.drop_column("correlation_rules", "ordering")
