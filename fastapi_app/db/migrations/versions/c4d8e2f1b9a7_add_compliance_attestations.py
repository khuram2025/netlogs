"""Add compliance_attestations table

Revision ID: c4d8e2f1b9a7
Revises: a1b9c4d2e7f3
Create Date: 2026-04-21 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4d8e2f1b9a7"
down_revision: Union[str, Sequence[str], None] = "a1b9c4d2e7f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_attestations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=False),
        sa.Column("control_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        # Optional proof upload (one file per attestation). Stored on
        # disk under the app's static tree and referenced here.
        sa.Column("proof_path", sa.String(length=512), nullable=True),
        sa.Column("proof_filename", sa.String(length=256), nullable=True),
        sa.Column("proof_mimetype", sa.String(length=64), nullable=True),
        sa.Column("proof_size", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices_device.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "device_id", "framework", "control_id",
            name="uq_attestation_device_framework_control",
        ),
    )
    op.create_index(
        "idx_attestation_device", "compliance_attestations", ["device_id"]
    )
    op.create_index(
        "idx_attestation_framework", "compliance_attestations",
        ["device_id", "framework"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_attestation_framework", table_name="compliance_attestations"
    )
    op.drop_index(
        "idx_attestation_device", table_name="compliance_attestations"
    )
    op.drop_table("compliance_attestations")
