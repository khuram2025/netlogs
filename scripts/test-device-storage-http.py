"""Check the deployed Devices page with a short-lived console-issued admin session."""
import json, re, ssl, subprocess, time, urllib.request
from http.cookiejar import CookieJar, Cookie

code='''
import asyncio,json
from sqlalchemy import select
from fastapi_app.db.database import async_session_maker
from fastapi_app.models.user import User
from fastapi_app.core.auth import create_session_token
from fastapi_app.api.dns_service import device_storage_summary
from fastapi_app.api.views import format_bytes
async def main():
 async with async_session_maker() as db:
  user=(await db.execute(select(User).where(User.username=='admin'))).scalar_one()
  assert user.is_active and user.role=='ADMIN'
  token=await create_session_token(user.id,user.username,user.role)
 totals,rows=device_storage_summary()
 assert not totals.get('unavailable_sources'),totals
 print(json.dumps({'token':token,'rows':{ip:{'count':r['log_count'],'bytes':r['total_raw_size'],'display':format_bytes(r['total_raw_size'])} for ip,r in rows.items()}}))
asyncio.run(main())
'''
data=json.loads(subprocess.check_output(['docker','exec','-i','zensheild-web-1','python'],input=code,text=True).strip().splitlines()[-1])
cookies=CookieJar()
cookies.set_cookie(Cookie(0,'zentryc_session',data.pop('token'),None,False,'127.0.0.1',False,False,'/',True,True,None,True,None,None,{},False))
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/opt/zensheild/certs/server.crt')),urllib.request.HTTPCookieProcessor(cookies))
try:
 start=time.monotonic()
 with opener.open('https://127.0.0.1/devices/',timeout=45) as response:
  assert response.status==200 and '/auth/login' not in response.geturl()
  page=response.read().decode()
 elapsed=time.monotonic()-start
 assert 'logs received during the last 24 hours' in page
 assert 'temporarily unavailable' not in page
 table=page.split('<!-- Device Management -->')[1]
 for ip,row in data['rows'].items():
  matches=[r for r in re.findall(r'<tr>(.*?)</tr>',table,re.S) if '>'+ip+'</a>' in r]
  # Historical logs can belong to deleted devices; only registered rows render.
  if matches:
   assert row['display'] in matches[0], (ip,'wrong byte estimate')
   assert f"{row['count']:,} logs / 24h" in matches[0], (ip,'wrong received count')
 print(json.dumps({'result':'passed','http_status':200,'page_seconds':round(elapsed,3),'received_storage':data['rows']}))
finally:
 opener.open('https://127.0.0.1/auth/logout',timeout=20).close()
