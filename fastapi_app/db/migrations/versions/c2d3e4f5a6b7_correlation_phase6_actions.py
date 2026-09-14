"""Correlation Phase 6: response actions column

Adds ``actions`` to ``correlation_rules`` — a JSON list of response actions
fired when the rule records a match (e.g. webhook POST, structured log).

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-05-20 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c2d3e4f5a6b7"
down_revision: Union[str, Sequence[str], None] = "b1c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("correlation_rules", sa.Column("actions", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("correlation_rules", "actions")
