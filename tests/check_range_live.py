"""Read-only SQL boundary and full-route verification for the reported range."""
import asyncio
import inspect
import ipaddress
import json
from datetime import datetime, timezone
from starlette.requests import Request
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.api import views
from fastapi_app.main import app

async def main():
    c = CH.get_client()
    ips = ['10.10.190.11','10.10.190.12','10.10.190.15','10.10.191.1',
           '10.10.193.13','10.10.193.14','10.10.199.15','10.10.99.15']
    for field in ['srcip','dstip']:
        for negate in [False, True]:
            condition = CH._build_field_condition(field,'10.10.190.12-10.10.193.13',negate)
            sql = f"SELECT {field} FROM (SELECT arrayJoin({ips!r}) AS {field}, toIPv4({field}) AS {field}_v4) WHERE {condition}"
            found = {r[0] for r in c.query(sql).result_rows}
            expected = {ip for ip in ips if (ipaddress.ip_address('10.10.190.12') <= ipaddress.ip_address(ip) <= ipaddress.ip_address('10.10.193.13')) != negate}
            assert found == expected, (field, negate, found)
            print(json.dumps({'boundary_field':field,'negated':negate,'passed':True}),flush=True)
    request = Request({'type':'http','method':'GET','path':'/logs/','headers':[],
                       'query_string':b'','scheme':'https','server':('localhost',443),
                       'app':app,'router':app.router})
    args = {k:getattr(p.default,'default',p.default) for k,p in inspect.signature(views.log_list).parameters.items()}
    args.update(request=request,db=None,srcip='10.10.190.12-10.10.193.13',
                action='deny',scope='internet',time_range='1h',per_page='100')
    start = datetime.now(timezone.utc)
    response = await views.log_list(**args)
    ctx = response.context
    assert not ctx.get('nql_error') and not ctx.get('error'), ctx.get('nql_error') or ctx.get('error')
    rows = ctx['logs']
    for row in rows:
        assert ipaddress.ip_address('10.10.190.12') <= ipaddress.ip_address(row['srcip']) <= ipaddress.ip_address('10.10.193.13')
        assert ctx['effective_start'] <= row['timestamp'].replace(tzinfo=timezone.utc) <= ctx['effective_end']
    print(json.dumps({'case':'reported-range','rows':len(rows),'all_ips_and_times_in_bounds':True,
                      'seconds':(datetime.now(timezone.utc)-start).total_seconds()}),flush=True)
    CH.close_client()

asyncio.run(main())
