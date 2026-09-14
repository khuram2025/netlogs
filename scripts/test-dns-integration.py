"""Real PostgreSQL/ClickHouse integration checks. Run inside a disposable appliance web container."""
import asyncio,json,uuid,hashlib
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from unittest.mock import patch
import httpx
from fastapi import FastAPI,Request
from sqlalchemy import text
from fastapi_app.api import dns_service as dns

async def main():
 await dns.initialize()
 app=FastAPI();app.include_router(dns.router)
 @app.middleware('http')
 async def user(request,call_next):
  role=request.headers.get('test-role')
  if role:request.state.current_user=SimpleNamespace(role=role)
  return await call_next(request)
 checks=0;sid=None;device=None
 packet='000081800001000100000000016104746573740000010001c00c000100010000003c0004c0000201'
 assert dns.answer_ips(packet)=='192.0.2.1'
 assert dns.answer_ips('not-a-packet')==''
 assert dns.answer_ips(packet[:30])==''
 checks+=3
 async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
  async def check(method,path,code,**kwargs):
   nonlocal checks
   r=await c.request(method,path,**kwargs)
   assert r.status_code==code,(path,r.status_code,r.text[:300]);checks+=1;return r
  try:
   await check('POST','/api/dns/sources',401,json={'ip_address':'198.18.0.36','hostname':'dns-acceptance'})
   await check('POST','/api/dns/sources',403,headers={'test-role':'ANALYST'},json={'ip_address':'198.18.0.36','hostname':'dns-acceptance'})
   r=await check('POST','/api/dns/sources',200,headers={'test-role':'ADMIN'},json={'ip_address':'198.18.0.36','hostname':'dns-acceptance'})
   source=r.json();sid=source['source_id'];device=source['device_id'];auth={'authorization':'Bearer '+sid+'.'+source['token']}
   event={'event_id':str(uuid.uuid4()),'timestamp':datetime.now(timezone.utc).isoformat(),'event_code':256,'fields':{'QNAME':'Test.Example.COM.','QTYPE':'1','Source':'198.18.0.50','TCP':'0','Port':'53000'}}
   batch={'batch_id':str(uuid.uuid4()),'hostname':'spoofed-name','agent_version':'test','events':[event]}
   raw=json.dumps(batch).encode()
   await check('POST','/api/dns/ingest',401,content=raw)
   await check('POST','/api/dns/ingest',401,headers={'authorization':'Bearer '+sid+'.'+'x'*43},content=raw)
   r=await check('POST','/api/dns/ingest',200,headers=auth,content=raw);assert r.json()['accepted']==1
   r=await check('POST','/api/dns/ingest',200,headers=auth,content=raw);assert r.json()['duplicate']
   altered={**batch,'hostname':'different'}
   await check('POST','/api/dns/ingest',409,headers=auth,json=altered)
   heartbeat={'batch_id':str(uuid.uuid4()),'hostname':'spoofed-name','events':[]}
   r=await check('GET','/api/dns/sources',200,headers={'test-role':'VIEWER'});before=next(x for x in r.json()['sources'] if x['id']==sid)
   assert before['hostname']=='dns-acceptance' and before['log_count']==1 and before['last_log_received']
   totals, storage = await asyncio.to_thread(dns.device_storage_summary)
   assert totals['total_rows'] >= 1 and storage['198.18.0.36']['log_count'] == 1
   assert storage['198.18.0.36']['total_raw_size'] > 0
   checks += 2
   await check('POST','/api/dns/ingest',200,headers=auth,json=heartbeat)
   r=await check('GET','/api/dns/sources',200,headers={'test-role':'VIEWER'});after=next(x for x in r.json()['sources'] if x['id']==sid)
   assert before['last_log_received']==after['last_log_received'] and after['log_count']==1
   await check('GET','/api/dns/events',403,headers={'test-role':'VIEWER'})
   r=await check('GET','/api/dns/events?device_ip=198.18.0.36&domain=example.com&domain_mode=suffix&qtype=A&transport=udp',200,headers={'test-role':'ANALYST'})
   assert len(r.json()['events'])==1,r.text
   row=r.json()['events'][0];assert row['qname']=='test.example.com' and row['src_ip']=='198.18.0.50' and row['device_name']=='dns-acceptance'
   r=await check('GET','/api/dns/events?device_ip=198.18.0.36&domain=example.com&domain_mode=exact',200,headers={'test-role':'ANALYST'});assert not r.json()['events']
   r=await check('GET',"/api/dns/events?device_ip=198.18.0.36&domain='+OR+1=1--",200,headers={'test-role':'ANALYST'});assert not r.json()['events']
   await check('GET','/api/dns/events?limit=501',422,headers={'test-role':'ANALYST'})
   await check('GET','/api/dns/events?hours=9999',422,headers={'test-role':'ANALYST'})
   await check('GET','/api/dns/events?offset=10001',422,headers={'test-role':'ANALYST'})
   await check('GET','/api/dns/events?resolved_ip=invalid',422,headers={'test-role':'ANALYST'})
   await check('GET','/api/dns/agent/package',403,headers={'test-role':'VIEWER'})
   package=await check('GET','/api/dns/agent/package',200,headers={'test-role':'ADMIN'});assert package.content.startswith(b'PK')
   await check('GET','/api/dns/agent/guide',200,headers={'test-role':'ADMIN'})
   r=await check('GET','/api/dns/stats?device_ip=198.18.0.36',200,headers={'test-role':'ANALYST'});assert r.json()['summary']['total']==1,r.text
   stats=r.json()
   assert stats['top_domains']==[{'qname':'test.example.com','count':1,'queries':1}]
   assert stats['top_clients']==[{'value':'198.18.0.50','count':1,'queries':1}]
   assert stats['record_types']==[{'value':'A','count':1,'queries':1}]
   assert stats['response_codes']==[]
   checks+=4
   invalid={**event,'timestamp':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}
   await check('POST','/api/dns/ingest',422,headers=auth,json={**batch,'batch_id':str(uuid.uuid4()),'events':[invalid]})
   await check('POST','/api/dns/ingest',422,headers=auth,json={**batch,'batch_id':str(uuid.uuid4()),'events':[event,event]})
   await check('POST','/api/dns/ingest',413,headers=auth,content=b'x'*(dns.MAX_BODY+1))
   async with dns.async_session_maker() as db:
    await db.execute(text("UPDATE devices_device SET status='REJECTED' WHERE id=:id"),{'id':device});await db.commit()
   await check('POST','/api/dns/ingest',403,headers=auth,json=heartbeat)
   async with dns.async_session_maker() as db:
    await db.execute(text("UPDATE devices_device SET status='APPROVED' WHERE id=:id"),{'id':device});await db.commit()
   # Simulate ambiguous delivery: ClickHouse already committed but PG receipt was lost.
   async with dns.async_session_maker() as db:
    await db.execute(text('DELETE FROM dns_batches WHERE source_id=:id'),{'id':uuid.UUID(sid)});await db.commit()
   await check('POST','/api/dns/ingest',200,headers=auth,content=raw)
   r=await check('GET','/api/dns/events?device_ip=198.18.0.36',200,headers={'test-role':'ANALYST'});assert len(r.json()['events'])==1,'ClickHouse retries must deduplicate'
   # Rotation must immediately revoke the old source token.
   await check('POST',f'/api/dns/sources/{sid}/rotate',200,headers={'test-role':'ADMIN'})
   await check('POST','/api/dns/ingest',401,headers=auth,json=heartbeat)
   print(f'PASS: {checks} DNS integration checks; authenticated intake, retry deduplication, source identity, health, filters, limits, RBAC and rotation.')
  finally:
   if sid:
    await asyncio.to_thread(lambda:dns.ClickHouseClient.get_client().command('ALTER TABLE windows_dns_events DELETE WHERE source_id={id:UUID}',parameters={'id':sid},settings={'mutations_sync':1}))
   if device:
    async with dns.async_session_maker() as db:
     await db.execute(text('DELETE FROM devices_device WHERE id=:id'),{'id':device});await db.commit()

asyncio.run(main())
