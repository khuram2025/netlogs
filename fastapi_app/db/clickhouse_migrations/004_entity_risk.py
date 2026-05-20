"""
ClickHouse migration 004: entity_risk table.

Phase 5 of the correlation engine overhaul. Each correlation match contributes
a weighted risk score to the entity it implicates; rows are append-only and an
entity's *current* risk is computed at query time with exponential time-decay
(so stale risk ages out). A separate evaluator promotes high-risk entities into
incidents.

ADD ... IF NOT EXISTS — safe to re-run.
"""

import logging

logger = logging.getLogger(__name__)


_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS entity_risk (
        timestamp DateTime64(3),
        entity_type LowCardinality(String),
        entity_value String,
        score Float64,
        rule_id UInt32,
        rule_name String,
        match_fingerprint String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (entity_value, timestamp)
    TTL toDateTime(timestamp) + INTERVAL 30 DAY DELETE
    """,
]


def upgrade(client):
    for stmt in _STATEMENTS:
        client.command(stmt.strip())
    logger.info("entity_risk table ensured in ClickHouse")
