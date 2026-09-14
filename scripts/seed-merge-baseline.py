import asyncio
from pathlib import Path
from sqlalchemy import select
from fastapi_app.db.database import init_db,async_session_maker
from fastapi_app.models.device import Device
from fastapi_app.models.credential import DeviceCredential
from fastapi_app.db.clickhouse import ClickHouseClient
async def main():
 await init_db()
 async with async_session_maker() as db:
  d=Device(ip_address='198.18.0.10',hostname='upgrade-preservation',status='APPROVED',parser='FORTINET',retention_days=90,log_count=7)
  db.add(d);await db.flush()
  c=DeviceCredential(device_id=d.id,username='test-fixture',credential_type='SSH');c.password='Disposable-fixture-only';db.add(c);await db.commit()
 Path('/app/data/credentials/legacy-device-credentials.key').write_bytes(Path('/app/fastapi_app/.credential_key').read_bytes())
 Path('/app/data/credentials/upgrade-fixture').touch()
 ClickHouseClient.ensure_table()
 ClickHouseClient.get_client().command("INSERT INTO syslogs (timestamp,device_ip,facility,severity,message,raw) VALUES (now(),'198.18.0.10',1,6,'merge-fixture','merge-fixture')", settings={'async_insert':0})
 print('PASS seeded 0.3.4 database, encrypted credential and event')
asyncio.run(main())
