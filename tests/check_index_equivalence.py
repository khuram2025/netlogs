"""Verify compound skip hints preserve real-data counts for all supported scopes."""
import json
from datetime import datetime, timedelta, timezone
from fastapi_app.db.clickhouse import ClickHouseClient as CH

c = CH.get_client()
now = datetime.now(timezone.utc).replace(microsecond=0)
start = now - timedelta(minutes=5)
for scope in ['internet', 'internal', 'inbound']:
    for device in [None, ['192.168.47.1_Campus'], ['192.168.47.1_WAN']]:
        query = f'srcip:172.20.30.46 action:deny|drop|block|reject scope:{scope}'
        where = CH._build_where_clause(device_ips=device, start_time=start, end_time=now, query_text=query)
        hints = CH._scoped_ip_index_hint(query, device)
        baseline = c.query(f'SELECT count() FROM syslogs WHERE {where} SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=10').result_rows
        indexed = c.query(f'SELECT count() FROM syslogs WHERE {where} AND '+ ' AND '.join(hints)+' SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=10').result_rows
        assert baseline == indexed, (scope, device, baseline, indexed)
        print(json.dumps({'scope':scope, 'device': device, 'counts_equal':True}), flush=True)
CH.close_client()
