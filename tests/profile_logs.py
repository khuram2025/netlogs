"""Read-only full template and individual query timings for the reported search."""
import asyncio
import inspect
import json
import os
import time
from unittest.mock import patch
from starlette.requests import Request
from fastapi_app.api import views
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.main import app

async def main():
    args = {k: getattr(p.default, 'default', p.default)
            for k, p in inspect.signature(views.log_list).parameters.items()}
    args.update(request=Request({'type': 'http', 'method': 'GET', 'path': '/logs/',
                                 'headers': [], 'query_string': b'',
                                 'scheme': 'https', 'server': ('localhost', 443),
                                 'app': app, 'router': app.router}),
                db=None, q='srcip:172.20.30.46', action='deny', scope='internet',
                time_range='7d', per_page='100')
    if os.environ.get('PROFILE_DEVICE'):
        args['device'] = os.environ['PROFILE_DEVICE']
    if os.environ.get('PROFILE_VIEW'):
        args['view'] = os.environ['PROFILE_VIEW']
    client_type = type(CH.get_client())
    query = client_type.query
    def measured(client, sql, *a, **kw):
        start = time.perf_counter()
        try:
            result = query(client, sql, *a, **kw)
            print(json.dumps({'query': ' '.join(sql.split())[:150],
                              'seconds': round(time.perf_counter()-start, 3),
                              'summary': result.summary}), flush=True)
            return result
        except Exception as e:
            print(json.dumps({'query': ' '.join(sql.split())[:150],
                              'seconds': round(time.perf_counter()-start, 3),
                              'error': type(e).__name__}), flush=True)
            raise
    start = time.perf_counter()
    with patch.object(client_type, 'query', measured):
        result = await views.log_list(**args)
    print(json.dumps({'full_render_seconds': round(time.perf_counter()-start, 3),
                      'bytes': len(result.body),
                      'rows': len(result.context.get('logs', [])),
                      'total': result.context.get('total_display'),
                      'error': result.context.get('nql_error')}), flush=True)
    CH.close_client()

asyncio.run(main())
