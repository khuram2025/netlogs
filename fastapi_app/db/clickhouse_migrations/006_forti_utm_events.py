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
it at insert time. Existing history is snapshotted during maintenance and
processed by the resumable background worker, without blocking startup or
silently skipping failed days.
"""

import logging

logger = logging.getLogger(__name__)


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


def upgrade(client):
    from fastapi_app.db.analytics_backfill import prepare
    prepare(client, 'forti_utm_events')
    for stmt in _STATEMENTS:
        client.command(stmt.strip())
    logger.info("forti_utm_events schema ready; history is processed after startup")
