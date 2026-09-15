"""
ClickHouse migration 002: Policy analytics daily aggregate tables.

Creates three AggregatingMergeTree tables populated by materialized views
on every INSERT into `syslogs`. Used by PolicyAnalyticsService to answer
analytics queries in ~5 ms instead of ~90 s on devices with 100 M+ rows.

History is snapshotted during the appliance maintenance window and processed
in bounded, replay-safe batches after startup. AggregatingMergeTree sums
duplicates; merge compaction does not make repeated INSERTs idempotent.
"""

import logging

logger = logging.getLogger(__name__)


# Tables + MVs are identical to what the ops team ran by hand; keep the
# exact DDL here so a fresh deploy reproduces the same shape.
_STATEMENTS = [
    # ── Per-policy daily hit counts ──────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS policy_hits_daily (
        device_ip IPv4 CODEC(ZSTD(1)),
        day Date CODEC(DoubleDelta, LZ4),
        policyname LowCardinality(String) CODEC(ZSTD(1)),
        hits SimpleAggregateFunction(sum, UInt64) CODEC(T64, LZ4),
        last_seen SimpleAggregateFunction(max, DateTime) CODEC(DoubleDelta, LZ4)
    ) ENGINE = AggregatingMergeTree
    PARTITION BY toYYYYMM(day)
    ORDER BY (device_ip, day, policyname)
    TTL day + toIntervalDay(45)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS policy_hits_daily_mv TO policy_hits_daily AS
    SELECT
        device_ip,
        toDate(timestamp) AS day,
        policyname,
        toUInt64(1) AS hits,
        toDateTime(timestamp) AS last_seen
    FROM syslogs
    WHERE policyname != ''
    """,

    # ── Implicit-deny 5-tuples (flows denied with no matching rule) ──
    """
    CREATE TABLE IF NOT EXISTS implicit_deny_daily (
        device_ip IPv4 CODEC(ZSTD(1)),
        day Date CODEC(DoubleDelta, LZ4),
        srcip String CODEC(ZSTD(1)),
        dstip String CODEC(ZSTD(1)),
        dstport UInt16 CODEC(T64, LZ4),
        proto UInt8 CODEC(T64, LZ4),
        hits SimpleAggregateFunction(sum, UInt64) CODEC(T64, LZ4)
    ) ENGINE = AggregatingMergeTree
    PARTITION BY toYYYYMM(day)
    ORDER BY (device_ip, day, srcip, dstip, dstport, proto)
    TTL day + toIntervalDay(45)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS implicit_deny_daily_mv TO implicit_deny_daily AS
    SELECT
        device_ip,
        toDate(timestamp) AS day,
        srcip, dstip, dstport, proto,
        toUInt64(1) AS hits
    FROM syslogs
    WHERE lower(action) IN ('deny','drop','block','reject','blocked','reset-both')
      AND srcip != ''
      AND (policyname = '' OR policyname = 'implicit deny')
    """,

    # ── Flow-pair daily counts (reachability matrix source) ──────
    """
    CREATE TABLE IF NOT EXISTS flow_pairs_daily (
        device_ip IPv4 CODEC(ZSTD(1)),
        day Date CODEC(DoubleDelta, LZ4),
        srcip String CODEC(ZSTD(1)),
        dstip String CODEC(ZSTD(1)),
        hits SimpleAggregateFunction(sum, UInt64) CODEC(T64, LZ4)
    ) ENGINE = AggregatingMergeTree
    PARTITION BY toYYYYMM(day)
    ORDER BY (device_ip, day, srcip, dstip)
    TTL day + toIntervalDay(45)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS flow_pairs_daily_mv TO flow_pairs_daily AS
    SELECT
        device_ip,
        toDate(timestamp) AS day,
        srcip, dstip,
        toUInt64(1) AS hits
    FROM syslogs
    WHERE srcip != '' AND dstip != ''
      AND match(srcip, '^[0-9.]+$')
      AND match(dstip, '^[0-9.]+$')
    """,
]


def upgrade(client):
    from fastapi_app.db.analytics_backfill import prepare
    for target in ('policy_hits_daily', 'implicit_deny_daily', 'flow_pairs_daily'):
        prepare(client, target)
    for stmt in _STATEMENTS:
        client.command(stmt.strip())
