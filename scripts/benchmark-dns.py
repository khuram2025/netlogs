"""Bounded synthetic query benchmark; run only on the disposable appliance database."""
import uuid,time,json,statistics
from datetime import datetime,timedelta,timezone
from fastapi_app.api.dns_service import ClickHouseClient,COLUMNS,execute_search,execute_stats
client=ClickHouseClient.get_client();sid=uuid.uuid4();now=datetime.now(timezone.utc)
try:
 start=time.monotonic()
 for batch in range(40):
  rows=[]
  for j in range(2500):
   i=batch*2500+j;ts=now-timedelta(seconds=i%3500,microseconds=i)
   rows.append([ts,now,now+timedelta(days=1),sid,uuid.uuid4(),'198.18.0.37','dns-benchmark',256,'query-received',f'198.18.1.{i%250+1}','198.18.0.37',50000,53,'udp',f'domain-{i%5000}.benchmark.invalid','A','','query','','','{}'])
  client.insert('windows_dns_events',rows,column_names=COLUMNS,settings={'async_insert':0})
 insert_seconds=time.monotonic()-start
 timings={}
 for label,extra in [('recent',{}),('domain',{'domain':'domain-123.benchmark.invalid','domain_mode':'exact'}),('client',{'src_ip':'198.18.1.124'})]:
  samples=[]
  for _ in range(5):
   start=time.monotonic();r=execute_search({'device_ip':'198.18.0.37','hours':'1','limit':'100',**extra});samples.append((time.monotonic()-start)*1000)
   assert r['events']
  timings[label]={'median_ms':round(statistics.median(samples),2),'max_ms':round(max(samples),2)}
 start=time.monotonic();stats=execute_stats({'device_ip':'198.18.0.37','hours':'1'});stats_seconds=time.monotonic()-start
 assert stats['summary']['total']==100000
 print(json.dumps({'events':100000,'direct_insert_seconds':round(insert_seconds,2),'query_timings':timings,'statistics_ms':round(stats_seconds*1000,2),'scope':'Synthetic ClickHouse query benchmark on disposable VM; not an end-to-end EPS rating'},indent=2))
finally:client.command('ALTER TABLE windows_dns_events DELETE WHERE source_id={id:UUID}',parameters={'id':str(sid)},settings={'mutations_sync':1})
