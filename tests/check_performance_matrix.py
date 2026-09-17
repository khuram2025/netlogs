"""Sequential real-data checks, including full HTML rendering; no raw log output."""
import asyncio
import inspect
import json
import time
import gzip
from datetime import datetime, timedelta, timezone
from starlette.requests import Request
from fastapi_app.api import views
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.main import app
from fastapi_app.services import nql_schema


async def main():
    devices = CH.get_distinct_devices()
    base = {'q': 'srcip:172.20.30.46', 'action': 'deny', 'scope': 'internet'}
    ranges = ['1m', '5m', '1h', '24h', '7d', '30d']
    cases = [(f'reported/{r}', dict(base, time_range=r)) for r in ranges]
    cases += [(f'reported/device-{i}', dict(base, time_range='7d', device=d)) for i, d in enumerate(devices)]
    for i, r in enumerate(ranges):
        cases += [(f'{r}/tcp-allow-443', {'time_range': r, 'protocol': 'TCP', 'action': 'accept', 'dstport': '443'}),
                  (f'{r}/udp-dns-device', {'time_range': r, 'protocol': 'UDP', 'dstport': '53', 'device': devices[i % len(devices)]}),
                  (f'{r}/exclude-ip-port', {'time_range': r, 'srcip': '172.20.30.46', 'srcip_not': '1', 'dstport': '443', 'dstport_not': '1'}),
                  (f'{r}/cidr-or-scope', {'time_range': r, 'q': 'srcip:172.20.30.0/24 (action:deny OR action:drop)', 'scope': 'internet'}),
                  (f'{r}/empty', {'time_range': r, 'srcip': '192.0.2.255', 'action': 'deny'})]
    cases += [('reported/page-two', dict(base, time_range='7d', page='2')),
              ('reported/200-rows', dict(base, time_range='7d', per_page='200')),
              ('reported/nql-stats', dict(base, time_range='7d', q=base['q']+' | stats count by action')),
              ('reported/aggregate', dict(base, time_range='7d', view='aggregate')),
              ('aggregate/1m', {'time_range': '1m', 'view': 'aggregate'}),
              ('aggregate/24h-port', {'time_range': '24h', 'view': 'aggregate', 'group_by': 'dstport'}),
              ('custom-history', dict(base, time_range='custom', start=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat(), end=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()))]
    reports = []
    request = Request({'type': 'http', 'method': 'GET', 'path': '/logs/', 'headers': [],
                       'query_string': b'', 'scheme': 'https', 'server': ('localhost', 443),
                       'app': app, 'router': app.router})
    for label, params in cases:
        args = {k: getattr(p.default, 'default', p.default) for k, p in inspect.signature(views.log_list).parameters.items()}
        args.update(request=request, db=None, per_page='100')
        args.update(params)
        started = time.perf_counter()
        response = await views.log_list(**args)
        ctx = response.context
        rows = ctx.get('logs', []) or ctx.get('agg_rows', []) or ctx.get('nql_rows', [])
        error = ctx.get('error') or ctx.get('nql_error')
        if not error and ctx.get('logs'):
            for row in ctx['logs']:
                if label.startswith('reported/'):
                    assert row['srcip'] == '172.20.30.46'
                    assert row['action'].lower() in ['deny', 'drop', 'block', 'reject']
                if params.get('protocol'):
                    assert row['proto'] == {'TCP': 6, 'UDP': 17}[params['protocol']]
                if params.get('device'):
                    assert str(row['device_ip']) + ('_'+row['vdom'] if row.get('vdom') else '') == params['device']
                if 'empty' in label:
                    raise AssertionError('Documentation-only IP unexpectedly matched')
        report = {'case': label, 'seconds': round(time.perf_counter()-started, 3), 'rows': len(rows),
                  'total': ctx.get('total_display'), 'error': error, 'html_bytes': len(response.body),
                  'gzip_bytes': len(gzip.compress(response.body, compresslevel=5))}
        reports.append(report)
        print(json.dumps(report), flush=True)
    for minutes in [1, 10080]:
        for prefix in ['172.20.30', '172.20.30.46', '192.0.2.255']:
            started = time.perf_counter()
            result = nql_schema.suggest_values('srcip', prefix, minutes=minutes)
            print(json.dumps({'suggest_minutes': minutes, 'prefix': prefix, 'seconds': round(time.perf_counter()-started, 3), 'values': len(result)}), flush=True)
    CH.close_client()
    failures = sum(bool(r['error']) for r in reports)
    print(json.dumps({'cases': len(reports), 'failures': failures}), flush=True)
    if failures:
        raise SystemExit(1)

asyncio.run(main())
