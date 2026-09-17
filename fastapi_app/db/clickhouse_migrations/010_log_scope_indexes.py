"""Cheap Internet classification and combined indexes for scoped IP searches.

The expression preserves the explorer's existing IPv4 scope definition.
Index backfill is an explicit maintenance operation, not a blocking startup job.
"""
from fastapi_app.services.nql_schema import v4_non_public_sql

STATEMENTS = [
    'ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS dst_is_public UInt8 '
    f'MATERIALIZED NOT {v4_non_public_sql("dstip_v4")}',
    '''ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_src_action_public
       cityHash64(srcip, action, dst_is_public) TYPE bloom_filter(0.001) GRANULARITY 1''',
    '''ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_src_action_public_vdom
       cityHash64(srcip, action, dst_is_public, vdom) TYPE bloom_filter(0.001) GRANULARITY 1''',
]

def upgrade(client):
    for statement in STATEMENTS:
        client.command(statement)
