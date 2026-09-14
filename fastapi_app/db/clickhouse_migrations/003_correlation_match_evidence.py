"""
ClickHouse migration 003: correlation_matches match-identity & evidence columns.

Phase 1 of the correlation engine overhaul. Adds columns so a match record
represents a *unique attack chain* rather than a scheduler tick:

  rule_version       UInt32   — rule definition version that produced the match
  match_fingerprint  String   — stable id of (rule, entity); drives suppression
  entity_type        LowCard  — canonical entity kind ('ip', 'user', ...)
  entity_value       String   — the entity the chain implicates
  first_seen         DT64(3)  — earliest *event* time in the matched evidence
  last_seen          DT64(3)  — latest *event* time in the matched evidence
  status             LowCard  — match lifecycle state ('open' by default)

`first_seen` / `last_seen` are event-chain times (from the matched log rows),
distinct from `timestamp`, which remains the engine *evaluation* time.

All statements use ADD COLUMN IF NOT EXISTS — in ClickHouse this is a
metadata-only operation (instant, non-blocking) and the migration is safe to
re-run.
"""

import logging

logger = logging.getLogger(__name__)


_STATEMENTS = [
    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "rule_version UInt32 DEFAULT 1",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "match_fingerprint String DEFAULT ''",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "entity_type LowCardinality(String) DEFAULT ''",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "entity_value String DEFAULT ''",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "first_seen DateTime64(3) DEFAULT toDateTime64(0, 3)",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "last_seen DateTime64(3) DEFAULT toDateTime64(0, 3)",

    "ALTER TABLE correlation_matches ADD COLUMN IF NOT EXISTS "
    "status LowCardinality(String) DEFAULT 'open'",
]


def upgrade(client):
    for stmt in _STATEMENTS:
        client.command(stmt)
    logger.info("correlation_matches evidence/identity columns ensured")
