"""Correlation Phase 5: risk_score column + correlation_incidents table

Adds ``risk_score`` to ``correlation_rules`` (risk points a match contributes
to its entity; 0 = auto-derive from severity) and creates the
``correlation_incidents`` table that groups related matches per entity.

Revision ID: b1c2d3e4f5a6
Revises: a7b8c9d0e1f2
Create Date: 2026-05-20 15:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "correlation_rules",
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "correlation_incidents",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("entity_type", sa.String(length=40), nullable=False,
                  server_default="ip"),
        sa.Column("entity_value", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False,
                  server_default="new"),
        sa.Column("severity", sa.String(length=20), nullable=False,
                  server_default="medium"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rule_names", sa.JSON(), nullable=True),
        sa.Column("mitre_tactics", sa.JSON(), nullable=True),
        sa.Column("matches", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_corr_incident_status", "correlation_incidents", ["status"])
    op.create_index("ix_corr_incident_entity", "correlation_incidents", ["entity_value"])


def downgrade() -> None:
    op.drop_index("ix_corr_incident_entity", table_name="correlation_incidents")
    op.drop_index("ix_corr_incident_status", table_name="correlation_incidents")
    op.drop_table("correlation_incidents")
    op.drop_column("correlation_rules", "risk_score")
