"""baseline: capture existing schema

Revision ID: 83988c93cc25
Revises:
Create Date: 2026-02-16

This is a baseline migration that represents the existing v3.0 database schema.
It is intentionally a no-op — the schema already exists in production databases.
For new installs, init_db() creates tables via Base.metadata.create_all().
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '83988c93cc25'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Baseline migration — existing schema is already in place.
    # This revision just establishes the Alembic version tracking.
    pass


def downgrade() -> None:
    # Cannot downgrade below baseline.
    pass
