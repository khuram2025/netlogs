"""Exercise the merged app against real isolated PostgreSQL/ClickHouse/Redis."""
import asyncio,base64,json,logging
from pathlib import Path
from unittest.mock import patch
import httpx
from sqlalchemy import select,text,inspect
from fastapi_app import main as web
from fastapi_app.db.database import Base,engine,async_session_maker
from fastapi_app.db.clickhouse import ClickHouseClient
from fastapi_app.models.user import User
from fastapi_app.models.device import Device
from fastapi_app.models.credential import DeviceCredential
from fastapi_app.core.auth import create_session_token
logging.getLogger().setLevel(logging.WARNING)
async def main():
 checks=0
 with patch.object(web,'start_scheduler'),patch.object(web,'stop_scheduler'):
  async with web.lifespan(web.app):
   async with engine.connect() as conn:
    def verify(sync):
     found=inspect(sync)
     for table in Base.metadata.sorted_tables:
      assert found.has_table(table.name),table.name
      missing=set(table.columns.keys())-{c['name'] for c in found.get_columns(table.name)}
      assert not missing,(table.name,missing)
    await conn.run_sync(verify)
   print('PASS all mapped PostgreSQL tables and columns exist')
   checks+=1
   cols={x[0] for x in ClickHouseClient.get_client().query('DESCRIBE syslogs').result_rows}
   assert {'log_time','ingest_time','session_id'}<=cols
   assert ClickHouseClient.get_client().query("SELECT count() FROM system.tables WHERE database=currentDatabase() AND name IN ('dns_logs','url_logs','forti_utm_events','windows_dns_events')").result_rows[0][0]==4
   checks+=2
   ch=ClickHouseClient.get_client()
   ch.command("INSERT INTO syslogs (timestamp,device_ip,facility,severity,srcip,dstip,message,raw,parsed_data) VALUES (now(),'198.18.0.10',1,6,'10.2.3.4','8.8.8.8','nql-fixture','nql-fixture',map('sessionid','42','sentbyte','1024','rcvdbyte','512','service','HTTPS'))", settings={'async_insert':0})
   row=ch.query("SELECT session_id,sent_bytes,recv_bytes,toString(srcip_v4) FROM syslogs WHERE message='nql-fixture'").result_rows[0]
   assert row==(42,1024,512,'10.2.3.4'),row
   from fastapi_app.services.nql_parser import compile_filter
   condition,_=compile_filter('srcip:10.0.0.0/8 sent_bytes:>=1000 scope:internet')
   assert ch.query("SELECT count() FROM syslogs WHERE "+condition).result_rows[0][0]==1
   checks+=2
   async with async_session_maker() as db:
    admin=(await db.execute(select(User).where(User.username=='admin'))).scalar_one()
    if Path('/app/data/credentials/upgrade-fixture').exists():
     credential=(await db.execute(select(DeviceCredential))).scalar_one()
     assert credential.password=='Disposable-fixture-only'
     assert not Path('/app/data/credentials/legacy-device-credentials.key').exists()
     assert Path('/app/data/credentials/device-credentials.key').stat().st_mode & 0o777==0o600
     assert ClickHouseClient.get_client().query("SELECT count() FROM syslogs WHERE message='merge-fixture'").result_rows[0][0]==1
     print('PASS legacy encrypted credential rotated; original event retained');checks+=4
    else:
     db.add(Device(ip_address='198.18.0.10',hostname='fresh-fixture',status='APPROVED',parser='FORTINET',retention_days=90,log_count=0));await db.commit()
    device=(await db.execute(select(Device).where(Device.ip_address=='198.18.0.10'))).scalar_one()
    did=device.id
    token=await create_session_token(admin.id,admin.username,admin.role)
   from fastapi_app.services.syslog_collector import SyslogCollector, get_or_create_device
   new_source=await get_or_create_device('198.18.0.99',b'<134>test unknown source')
   assert new_source[0]=='PENDING' and len(new_source)==3
   collector=SyslogCollector()
   collector._raw_queue.append(('198.18.0.10',b'<134>date=2026-09-14 time=13:00:00 tz="+0300" devname="test" type="traffic" subtype="forward" srcip=10.2.3.5 dstip=8.8.4.4 srcport=53000 dstport=443 proto=6 action="accept" sessionid=43 sentbyte=10 rcvdbyte=20 msg="collector-fixture"'))
   await collector._process_batch()
   assert collector.metrics.logs_processed==1 and collector.metrics.flush_errors==0
   await collector.stop()
   assert ch.query("SELECT count() FROM syslogs WHERE srcip='10.2.3.5' AND session_id=43").result_rows[0][0]==1
   print('PASS source approval and actual collector batch parsing/persistence');checks+=3
   async with httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app,raise_app_exceptions=True),base_url='https://test',follow_redirects=False) as client:
    client.cookies.set('zentryc_session',token)
    paths=['/system/','/system/updates/','/devices/','/logs/','/threats/url-dns/','/threats/url-dns/?tab=url','/correlation/','/reports/','/reports/executive','/reports/security','/reports/productivity','/reports/bandwidth','/reports/top-users','/analytics/traffic','/api/correlation/rules/','/api/correlation/schema','/api/system/time/','/api/logs/facets?field=srcip','/api/analytics/traffic','/api/dns/events','/api/dns/sources','/api/threats/dns-logs','/api/threats/dns-logs/stats']
    paths += ['/api/web-activity/'+x for x in ['summary','timeline','productivity','users','sites','categories','searches','blocked','bandwidth','logs','facets']]
    for path in paths:
     response=await client.get(path)
     expected=303 if path=='/system/updates/' else 200
     assert response.status_code==expected,(path,response.status_code,response.text[:300])
     if expected==303:assert response.headers['location']=='/system/#updates'
     if path=='/api/analytics/traffic':
      assert response.json()['totals']['bytes']>=1536,response.text[:300]
     checks+=1
     print('PASS GET',path)
    csrf=client.cookies.get('zentryc_csrf');headers={'X-CSRF-Token':csrf}
    proof=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jR2kAAAAASUVORK5CYII=')
    url=f'/api/devices/{did}/attestations/cis_v8/1.1'
    response=await client.put(url,headers=headers,data={'status':'pass','include_in_report':'true','notes':'Disposable integration proof'},files={'proof':('proof.png',proof,'image/png')})
    assert response.status_code==200,response.text[:300]
    proof_url=response.json()['proof_url'];assert (await client.get(proof_url)).content==proof
    checks+=2
    response=await client.get(f'/devices/{did}/analytics/report.pdf')
    assert response.status_code==200 and response.content.startswith(b'%PDF'),(response.status_code,response.text[:200])
    print('PASS compliance upload, authenticated retrieval and real PDF rendering');checks+=1
    response=await client.post('/system/time/',headers=headers,data={'display_tz':'Asia/Riyadh','source_tz':'Asia/Riyadh'})
    assert response.status_code==303 and '/system/storage-monitor/' in response.headers['location']
    time_data=(await client.get('/api/system/time/')).json();assert time_data['display_tz']=='Asia/Riyadh' and time_data['source_tz']=='Asia/Riyadh';checks+=2
    assert (await client.post('/api/appliance/storage.plan',json={'action':'rescan'})).status_code==403;checks+=1
    await client.get('/auth/logout')
    assert (await client.get(proof_url)).status_code==401;checks+=1
   print(json.dumps({'merged_app_checks':checks,'result':'passed'}))
asyncio.run(main())
