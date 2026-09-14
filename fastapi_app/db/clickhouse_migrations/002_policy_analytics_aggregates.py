"""
ClickHouse migration 002: Policy analytics daily aggregate tables.

Creates three AggregatingMergeTree tables populated by materialized views
on every INSERT into `syslogs`. Used by PolicyAnalyticsService to answer
analytics queries in ~5 ms instead of ~90 s on devices with 100 M+ rows.

Backfill from existing syslogs runs at the end of `upgrade()` and is
idempotent — `INSERT INTO … SELECT` is a no-op on an already-populated
aggregate since the rows sum cleanly at merge time.
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


# Backfill from existing syslogs so the aggregates are useful immediately on
# upgrade. These are idempotent because AggregatingMergeTree sums rows with
# the same sort-key at merge time — re-running adds duplicates we later
# compact away, but for a clean migration we guard on an empty-table check.
_BACKFILLS = [
    (
        "policy_hits_daily",
        """
        INSERT INTO policy_hits_daily
        SELECT device_ip, toDate(timestamp) AS day, policyname,
               count() AS hits, max(toDateTime(timestamp)) AS last_seen
        FROM syslogs WHERE policyname != ''
        GROUP BY device_ip, day, policyname
        """,
    ),
    (
        "implicit_deny_daily",
        """
        INSERT INTO implicit_deny_daily
        SELECT device_ip, toDate(timestamp) AS day, srcip, dstip, dstport, proto,
               count() AS hits
        FROM syslogs
        WHERE lower(action) IN ('deny','drop','block','reject','blocked','reset-both')
          AND srcip != '' AND (policyname = '' OR policyname = 'implicit deny')
        GROUP BY device_ip, day, srcip, dstip, dstport, proto
        """,
    ),
    (
        "flow_pairs_daily",
        """
        INSERT INTO flow_pairs_daily
        SELECT device_ip, toDate(timestamp) AS day, srcip, dstip, count() AS hits
        FROM syslogs
        WHERE srcip != '' AND dstip != ''
          AND match(srcip, '^[0-9.]+$') AND match(dstip, '^[0-9.]+$')
        GROUP BY device_ip, day, srcip, dstip
        """,
    ),
]


def upgrade(client):
    for stmt in _STATEMENTS:
        client.command(stmt.strip())
    for table, sql in _BACKFILLS:
        try:
            count = int(list(client.query(f"SELECT count() FROM {table}").result_rows)[0][0])
        except Exception:
            count = 0
        if count == 0:
            logger.info(f"Backfilling {table} from syslogs…")
            client.command(sql.strip())
        else:
            logger.info(f"Skipping backfill of {table} ({count:,} rows already present)")
