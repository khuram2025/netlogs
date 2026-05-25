"""device timezone column

Adds an optional ``timezone`` column to ``devices_device``. The syslog
collector uses it to convert device-local timestamps (which most vendors
emit without an offset) to UTC for storage. NULL means "use the global
default source timezone" — set in /system Time settings.

Revision ID: d8e1c4b6a912
Revises: c2d3e4f5a6b7
Create Date: 2026-05-25 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d8e1c4b6a912"
down_revision: Union[str, Sequence[str], None] = "c2d3e4f5a6b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "devices_device",
        sa.Column("timezone", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices_device", "timezone")
