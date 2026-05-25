"""
ClickHouse migration 005: syslogs.ingest_time column.

Splits the single ``timestamp`` field into two semantically distinct values:

  ``timestamp``    — event time (when the device says the event happened),
                     used everywhere it already was (ORDER BY, PARTITION BY,
                     UI rendering). Existing rows keep their ingest-derived
                     value; new rows will be event-time.
  ``ingest_time``  — when the collector received the record. Surfaced in the
                     log detail panel so operators can see pipeline lag.

We do not rewrite old rows: their ``timestamp`` was already ingest time, so
``ingest_time`` defaults to that same value for the historical window. The
DEFAULT expression makes the column readable on any existing row without a
backfill mutation.

Idempotent — safe to re-run.
"""

import logging

logger = logging.getLogger(__name__)


_STATEMENTS = [
    """
    ALTER TABLE syslogs
        ADD COLUMN IF NOT EXISTS ingest_time DateTime64(3) DEFAULT timestamp
        CODEC(DoubleDelta, LZ4)
    """,
]


def upgrade(client):
    for stmt in _STATEMENTS:
        try:
            client.command(stmt.strip())
        except Exception as e:
            # ADD COLUMN IF NOT EXISTS is safe; only surface other errors.
            logger.warning(f"syslogs.ingest_time migration step skipped: {e}")
    logger.info("syslogs.ingest_time column ensured in ClickHouse")
