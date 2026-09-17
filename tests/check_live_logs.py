"""Read-only route/ClickHouse integration checks. Emits metrics, never raw logs."""
import asyncio
import inspect
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi_app.api import views
from fastapi_app.db.clickhouse import ClickHouseClient as CH

def defaults(fn, **values):
    args = {k: getattr(p.default, 'default', p.default) for k, p in inspect.signature(fn).parameters.items()}
    args.update(values)
    return args

async def main():
    reports = []
    devices = CH.get_distinct_devices()
    print(json.dumps({'discovered_devices': len(devices)}), flush=True)
    cases = [(f'{r}/device-{i}', {'time_range': r, 'device': device})
             for r in ['1m', '5m', '1h', '24h', '7d', '30d']
             for i, device in enumerate([None] + devices)]
    # Every toolbar/sidebar filter family, exclusions and meaningful combinations.
    sample = CH.search_logs(limit=1)[0]
    for key in ['srcip', 'dstip', 'srcport', 'dstport', 'application', 'policyname',
                'src_zone', 'dst_zone', 'session_end_reason', 'log_type', 'threat_id']:
        value = str(sample.get(key) or '')
        if value:
            cases.append((key, {key: value, 'time_range': '1m'}))
            if key in ['srcip', 'dstip', 'srcport', 'dstport']:
                cases.append((key + '-not', {key: value, key + '_not': '1', 'time_range': '1m'}))
    cases += [('protocol-TCP', {'protocol': 'TCP', 'time_range': '1m'}),
              ('protocol-UDP', {'protocol': 'UDP', 'time_range': '1m'}),
              ('allow', {'action': 'accept', 'time_range': '1m'}),
              ('deny', {'action': 'deny', 'time_range': '1m'}),
              ('internet', {'scope': 'internet', 'time_range': '1m'}),
              ('combined', {'protocol': 'TCP', 'dstport': '443', 'action': 'accept', 'time_range': '1m'}),
              ('nql-aggregate', {'q': '| stats count by action', 'time_range': '1m'}),
              ('aggregate', {'view': 'aggregate', 'group_by': 'dstport', 'time_range': '1m'}),
              ('page-two', {'page': '2', 'time_range': '1m'}),
              ('empty', {'srcip': '192.0.2.255', 'time_range': '1m'})]
    now = datetime.now(timezone.utc)
    cases.append(('custom-utc', {'time_range': 'custom', 'start': (now-timedelta(minutes=10)).isoformat(), 'end': (now-timedelta(minutes=5)).isoformat()}))
    with patch.object(views, '_render', side_effect=lambda name, request, ctx: ctx):
        for label, params in cases:
            started = time.perf_counter()
            ctx = await views.log_list(**defaults(views.log_list, request=None, db=None, per_page='10', **params))
            error = ctx.get('error') or ctx.get('nql_error')
            rows = ctx.get('logs', []) or ctx.get('agg_rows', []) or ctx.get('nql_rows', [])
            if not error and params.get('device'):
                for row in ctx['logs']:
                    display = str(row['device_ip']) + ('_' + row['vdom'] if row.get('vdom') else '')
                    assert display == params['device'], 'Device filter returned another device'
            report = {'case': label, 'seconds': round(time.perf_counter()-started, 3),
                      'rows': len(rows), 'total': ctx.get('total_display'), 'error': error}
            reports.append(report)
            print(json.dumps(report), flush=True)
    CH.close_client()
    print(json.dumps({'cases': len(reports), 'failures': sum(bool(r['error']) for r in reports)}), flush=True)
    if any(r['error'] for r in reports):
        raise SystemExit(1)

asyncio.run(main())
