"""Migration 009: incrementally maintained device directory for the log explorer.

Creation is idempotent. Backfill may be repeated because max is idempotent;
installations should run it once in bounded historical time slices.
"""

STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS log_device_catalog (
        device_ip IPv4, vdom String,
        last_seen SimpleAggregateFunction(max, DateTime64(3))
    ) ENGINE = AggregatingMergeTree ORDER BY (device_ip, vdom)""",
    """CREATE MATERIALIZED VIEW IF NOT EXISTS log_device_catalog_mv
    TO log_device_catalog AS
    SELECT device_ip, vdom, max(timestamp) AS last_seen
    FROM syslogs GROUP BY device_ip, vdom""",
]

def upgrade(client):
    for statement in STATEMENTS:
        client.command(statement)
