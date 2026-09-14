"""
ClickHouse migration 006: forti_utm_events — FortiGate AV / IPS events as a
typed table.

The Threats dashboard unions Palo Alto `pa_threat_logs` with FortiGate UTM
data. Webfilter and DNS rows already land in the typed `url_logs` / `dns_logs`
tables, but antivirus and IPS events (`utm/virus`, `utm/ips`) were extracted
from the `parsed_data` Map in `syslogs` on every request. Those rows are rare
(~1k/day) yet sprinkled through every granule, so the bloom-filter on
log_type prunes almost nothing and each request read the Map for the whole
window — ~12 GiB over 7 days, for a few thousand rows.

This creates a small MergeTree with the fields the dashboard needs, already
mapped onto the pa_threat_logs vocabulary, and a materialized view that fills
it at insert time. Existing history is backfilled a day at a time, bounded,
so a slow day is skipped with a warning rather than blocking startup — the
MV covers everything from now on regardless.

Idempotent — safe to re-run.
"""

import logging
from datetime import date, timedelta

logger = logging.getLogger(__name__)

BACKFILL_DAYS = 30   # matches the syslogs TTL

# The SELECT shared by the MV and the backfill. Column names follow
# pa_threat_logs so the dashboard can UNION ALL without renaming.
_EXTRACT_SELECT = """
    SELECT
        timestamp,
        toString(device_ip)                                   AS device_ip,
        parsed_data['vd']                                     AS vsys,
        if(log_type = 'utm/virus', 'virus', 'vulnerability')  AS log_subtype,
        multiIf(
            parsed_data['level'] IN ('emergency','alert','critical'), 'critical',
            parsed_data['level'] = 'error',   'high',
            parsed_data['level'] = 'warning', 'medium',
            parsed_data['level'] = 'notice',  'low',
            'informational')                                  AS severity,
        parsed_data['direction']                              AS direction,
        action,
        srcip                                                 AS src_ip,
        dstip                                                 AS dest_ip,
        srcport                                               AS src_port,
        dstport                                               AS dest_port,
        multiIf(proto = 6, 'tcp', proto = 17, 'udp', proto = 1, 'icmp',
                toString(proto))                              AS transport,
        parsed_data['srcintf']                                AS src_zone,
        parsed_data['dstintf']                                AS dest_zone,
        coalesce(nullIf(parsed_data['user'],''), parsed_data['srcuser'], '')  AS src_user,
        parsed_data['dstuser']                                AS dest_user,
        coalesce(nullIf(parsed_data['app'],''), parsed_data['appcat'], '')    AS application,
        coalesce(nullIf(policyname,''), parsed_data['policyid'], '')          AS rule,
        coalesce(nullIf(parsed_data['threatid'],''), parsed_data['attackid'], '') AS threat_id,
        if(log_type = 'utm/virus',
           coalesce(nullIf(parsed_data['virus'],''), parsed_data['msg'], ''),
           coalesce(nullIf(parsed_data['attack'],''), parsed_data['msg'], '')) AS threat_name,
        if(log_type = 'utm/virus', 'virus',
           coalesce(nullIf(parsed_data['attackid'],''), 'ips'))               AS threat_category,
        parsed_data['contenttype']                            AS content_type,
        parsed_data['agent']                                  AS user_agent,
        parsed_data['httpmethod']                             AS http_method,
        parsed_data['referralurl']                            AS referrer,
        coalesce(nullIf(parsed_data['reason'],''), parsed_data['msg'], '')    AS reason,
        parsed_data['filename']                               AS file_name,
        parsed_data['filehash']                               AS file_hash,
        parsed_data['filetype']                               AS file_type,
        session_id,
        parsed_data['srccountry']                             AS src_location,
        parsed_data['dstcountry']                             AS dest_location
    FROM syslogs
    WHERE log_type IN ('utm/virus', 'utm/ips')
"""

_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS forti_utm_events (
        timestamp       DateTime64(3) CODEC(DoubleDelta, LZ4),
        device_ip       String CODEC(ZSTD(1)),
        vsys            LowCardinality(String),
        log_subtype     LowCardinality(String),
        severity        LowCardinality(String),
        direction       LowCardinality(String),
        action          LowCardinality(String),
        src_ip          String CODEC(ZSTD(1)),
        dest_ip         String CODEC(ZSTD(1)),
        src_port        UInt16 CODEC(T64, LZ4),
        dest_port       UInt16 CODEC(T64, LZ4),
        transport       LowCardinality(String),
        src_zone        LowCardinality(String),
        dest_zone       LowCardinality(String),
        src_user        String DEFAULT '' CODEC(ZSTD(1)),
        dest_user       String DEFAULT '' CODEC(ZSTD(1)),
        application     LowCardinality(String),
        rule            LowCardinality(String),
        threat_id       String DEFAULT '' CODEC(ZSTD(1)),
        threat_name     String DEFAULT '' CODEC(ZSTD(1)),
        threat_category LowCardinality(String),
        content_type    LowCardinality(String),
        user_agent      String DEFAULT '' CODEC(ZSTD(3)),
        http_method     LowCardinality(String),
        referrer        String DEFAULT '' CODEC(ZSTD(3)),
        reason          String DEFAULT '' CODEC(ZSTD(1)),
        file_name       String DEFAULT '' CODEC(ZSTD(1)),
        file_hash       String DEFAULT '' CODEC(ZSTD(1)),
        file_type       LowCardinality(String),
        session_id      UInt64 DEFAULT 0 CODEC(T64, LZ4),
        src_location    LowCardinality(String),
        dest_location   LowCardinality(String),
        INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_threat_name threat_name TYPE bloom_filter(0.01) GRANULARITY 4
    ) ENGINE = MergeTree
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (log_subtype, timestamp)
    TTL timestamp + toIntervalMonth(6)
    SETTINGS index_granularity = 8192
    """,
    f"""
    CREATE MATERIALIZED VIEW IF NOT EXISTS forti_utm_events_mv TO forti_utm_events AS
    {_EXTRACT_SELECT}
    """,
]


def _backfill(client) -> None:
    """Fill history a day at a time. Each day is bounded; one that cannot finish
    is logged and skipped (the MV already covers new rows)."""
    rows = client.query("SELECT count() FROM forti_utm_events").result_rows
    if rows and rows[0][0] > 0:
        logger.info(f"Skipping forti_utm_events backfill ({rows[0][0]:,} rows already present)")
        return

    today = date.today()
    total = 0
    for back in range(BACKFILL_DAYS, -1, -1):
        day = today - timedelta(days=back)
        sql = (
            f"INSERT INTO forti_utm_events {_EXTRACT_SELECT} "
            f"AND toDate(timestamp) = toDate('{day.isoformat()}')"
        )
        try:
            client.command(sql, settings={'max_execution_time': 90})
            got = client.query(
                f"SELECT count() FROM forti_utm_events WHERE toDate(timestamp) = toDate('{day.isoformat()}')"
            ).result_rows[0][0]
            total += got
        except Exception as e:
            logger.warning(f"forti_utm_events backfill skipped {day}: {e}")
    # Today's rows can arrive twice: through the MV (live since it was created
    # a moment ago) and through the backfill of today. Rows are byte-identical,
    # so a deduplicating merge collapses them.
    try:
        client.command("OPTIMIZE TABLE forti_utm_events FINAL DEDUPLICATE",
                       settings={'receive_timeout': 300})
    except Exception as e:
        logger.warning(f"forti_utm_events dedupe skipped: {e}")
    logger.info(f"forti_utm_events backfilled {total:,} rows over {BACKFILL_DAYS + 1} days")


def upgrade(client):
    for stmt in _STATEMENTS:
        client.command(stmt.strip())
    _backfill(client)
    logger.info("forti_utm_events table + MV ensured in ClickHouse")
