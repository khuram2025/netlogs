"""Add include_in_report flag + make status nullable on compliance_attestations

Revision ID: d7e9f3a4b2c1
Revises: c4d8e2f1b9a7
Create Date: 2026-04-21 14:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d7e9f3a4b2c1"
down_revision: Union[str, Sequence[str], None] = "c4d8e2f1b9a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # A row can now exist purely to carry the ``include_in_report = false``
    # flag (excluded from the PDF) without the reviewer having to also pick
    # a status. Make ``status`` nullable so the UI doesn't have to
    # synthesise one.
    op.alter_column(
        "compliance_attestations", "status",
        existing_type=sa.String(length=16),
        nullable=True,
    )
    op.add_column(
        "compliance_attestations",
        sa.Column(
            "include_in_report", sa.Boolean(),
            server_default=sa.text("true"), nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("compliance_attestations", "include_in_report")
    op.alter_column(
        "compliance_attestations", "status",
        existing_type=sa.String(length=16),
        nullable=False,
    )
