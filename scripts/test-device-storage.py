"""Run inside a disposable appliance. Fixtures use a unique temporary database."""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
import clickhouse_connect
from jinja2 import Environment, FileSystemLoader, ChoiceLoader, DictLoader
from fastapi_app.api import dns_service as dns
from fastapi_app.db.clickhouse import ClickHouseClient
from fastapi_app.core.config import settings

database = 'test_device_storage_' + uuid.uuid4().hex
admin = ClickHouseClient.get_client()
assert database.startswith('test_device_storage_') and database.removeprefix('test_device_storage_').isalnum()
admin.command(f'CREATE DATABASE {database}')
client = clickhouse_connect.get_client(host=settings.clickhouse_host, port=settings.clickhouse_port,
    username=settings.clickhouse_user, password=settings.clickhouse_password, database=database)
checks = []
try:
    client.command('''CREATE TABLE syslogs (timestamp DateTime64(3,'UTC'),
        ingest_time DateTime64(3,'UTC'),device_ip IPv4,vdom String,raw String)
        ENGINE=MergeTree ORDER BY(device_ip,timestamp)''')
    client.command('''CREATE TABLE windows_dns_events (timestamp DateTime64(6,'UTC'),
        received_at DateTime64(6,'UTC'),device_ip String,event_id UUID,raw_fields String)
        ENGINE=ReplacingMergeTree(received_at) ORDER BY(device_ip,timestamp,event_id)''')
    now = datetime.now(timezone.utc) - timedelta(minutes=1)
    old = now - timedelta(days=3)
    client.insert('syslogs', [[old,now,'192.0.2.10','root','a'*80],
        [old,now,'192.0.2.10','branch','b'*90],
        [now,old,'192.0.2.10','root','old receipt'],
        [now,now+timedelta(days=1),'192.0.2.10','root','future receipt']],
        column_names=['timestamp','ingest_time','device_ip','vdom','raw'])
    event = uuid.uuid4()
    client.insert('windows_dns_events',[[old,now,'192.0.2.20',event,'x'*120],
        [old,now+timedelta(seconds=1),'192.0.2.20',event,'x'*120],
        [old,now,'192.0.2.10',uuid.uuid4(),'mixed source'],
        [now,old,'192.0.2.20',uuid.uuid4(),'old receipt']],
        column_names=['timestamp','received_at','device_ip','event_id','raw_fields'])
    with patch.object(ClickHouseClient,'get_client',return_value=client):
        start=time.monotonic()
        rows=ClickHouseClient.get_per_device_storage()
        assert len(rows)==1 and rows[0]['device_ip']=='192.0.2.10' and rows[0]['log_count']==2,rows
        assert rows[0]['total_raw_size']>0
        checks.append('receipt window, VDOM aggregation, expired/future exclusion')
        metadata=client.query("SELECT sum(rows),sum(data_uncompressed_bytes) FROM system.parts WHERE database=currentDatabase() AND table='syslogs' AND active=1").result_rows[0]
        assert rows[0]['total_raw_size']==int(metadata[1]/metadata[0]*2)
        checks.append('current-database metadata and byte calculation')
        totals,by_ip=dns.device_storage_summary()
        assert by_ip['192.0.2.10']['log_count']==3 and by_ip['192.0.2.20']['log_count']==1,by_ip
        assert all(r['total_raw_size']>0 for r in by_ip.values())
        assert not totals['unavailable_sources']
        checks.append('DNS delayed events, deduplication, mixed-source total')
        elapsed=time.monotonic()-start
        with patch.object(ClickHouseClient,'get_per_device_storage',side_effect=RuntimeError('fixture unavailable')):
            partial_totals,partial=dns.device_storage_summary()
            assert partial_totals['unavailable_sources']==['syslog'] and partial['192.0.2.20']['log_count']==1
        with patch.object(dns,'_dns_storage_summary',side_effect=RuntimeError('fixture unavailable')):
            partial_totals,partial=dns.device_storage_summary()
            assert partial_totals['unavailable_sources']==['Windows DNS'] and partial['192.0.2.10']['log_count']==2
        checks.append('query failure preserves the other source and marks partial results')
    env=Environment(loader=ChoiceLoader([DictLoader({'base.html':'{% block content %}{% endblock %}',
        'devices/dns_sources.html':''}),FileSystemLoader('/app/fastapi_app/templates')]),autoescape=True)
    env.filters['timesince']=lambda value:'1 minute'
    device=lambda ip:SimpleNamespace(id=1,ip_address=ip,hostname='fixture',parser_display='DNS',status='APPROVED',retention_days=30,last_log_received=None,log_count=4)
    def render(stats,mapping):
        return env.get_template('devices/device_list.html').render(devices=[device('192.0.2.20'),device('192.0.2.99')],
            storage_stats=stats,device_storage_map=mapping,format_bytes=lambda v:f'{v} B',format_number=lambda v:f'{v:,}',url_for=lambda *a,**kw:'/fixture/')
    html=render(totals,by_ip)
    assert '1 logs / 24h' in html and 'No logs received in 24h' in html and 'Unavailable' not in html
    html=render({'unavailable':True,'unavailable_sources':['syslog','Windows DNS']},{})
    assert 'Unavailable' in html and 'No logs received in 24h' not in html
    checks.append('template distinguishes nonzero, no recent logs, and unavailable')
    print(json.dumps({'result':'passed','checks':checks,'query_seconds':round(elapsed,3)}))
finally:
    client.close()
    admin.command(f'DROP DATABASE {database} SYNC')
