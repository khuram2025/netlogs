"""Storage GUI/API acceptance using a short-lived console-issued administrator session."""
import json
import ssl
import subprocess
import time
import urllib.request
import urllib.error
from http.cookiejar import CookieJar, Cookie
from pathlib import Path

token_code='''
import asyncio
from sqlalchemy import select
from fastapi_app.db.database import async_session_maker
from fastapi_app.models.user import User
from fastapi_app.core.auth import create_session_token
async def main():
    async with async_session_maker() as db:
        user=(await db.execute(select(User).where(User.username=='admin'))).scalar_one()
        assert user.is_active and user.role=='ADMIN'
        print(await create_session_token(user.id,user.username,user.role))
asyncio.run(main())
'''
token=subprocess.check_output(['docker','exec','-i','zensheild-web-1','python'],input=token_code,text=True).strip().splitlines()[-1]
cookies=CookieJar()
cookies.set_cookie(Cookie(0,'zentryc_session',token,None,False,'127.0.0.1',False,False,'/',True,True,None,True,None,None,{},False))
ctx=ssl.create_default_context(cafile='/opt/zensheild/certs/server.crt')
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(cookies))
def request(path,body=None,csrf=True):
    headers={}
    if body is not None:
        headers={'Content-Type':'application/json'}
        if csrf:headers['X-CSRF-Token']=next((c.value for c in cookies if c.name=='zentryc_csrf'),'')
    req=urllib.request.Request('https://127.0.0.1'+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
    try:
        with opener.open(req,timeout=120) as response:return response.status,response.read()
    except urllib.error.HTTPError as e:return e.code,e.read()
def api(op,body=None,status=200):
    code,raw=request('/api/appliance/'+op,body or {})
    assert code==status,(op,code,raw[:300])
    return json.loads(raw)
try:
    code,page=request('/system/')
    assert code==200 and b'Grow system filesystem' in page
    print('PASS storage management page includes system growth and disk discovery')
    code,page=request('/system/storage-monitor/')
    assert code==200 and b'Host filesystem not mounted' not in page and b'/srv/zenshield/clickhouse' in page
    assert b'Storage Monitor' in page
    print('PASS storage monitor renders real host mounts without the obsolete hostfs warning')
    code,raw=request('/api/system/disk-usage/')
    data=json.loads(raw);assert code==200 and data['disk']['mount']=='/srv/zenshield/clickhouse'
    print('PASS live disk usage API reports the ClickHouse filesystem')
    api('storage.plan',{'action':'initialize','disk':'/dev/sda'},400)
    api('storage.plan',{'action':'grow','volume':'clickhouse','size_gib':1},400)
    assert request('/api/appliance/storage.plan',{'action':'rescan'},csrf=False)[0]==403
    print('PASS protected disk, shrink and missing CSRF requests are rejected')
    for invalid in ({'syslogs_max_size_gb': -1}, {'cleanup_trigger_percent': 101}, {'cleanup_target_percent': 99, 'cleanup_trigger_percent': 80}, {'auto_cleanup_enabled': 'yes'}):
        assert request('/api/system/storage-settings/', invalid)[0] == 400
    print('PASS invalid quota and cleanup settings are rejected without saving')
    plan=api('storage.plan',{'action':'rescan'})
    api('storage.commit',{'token':plan['token'],'confirmation':'wrong'},400)
    job=api('storage.commit',{'token':plan['token'],'confirmation':plan['confirmation']})
    api('storage.commit',{'token':plan['token'],'confirmation':plan['confirmation']},400)
    for _ in range(60):
        current=next(j for j in api('storage')['jobs'] if j['id']==job['id'])
        if current['state']!='running':break
        time.sleep(1)
    assert current['state']=='completed',current
    print('PASS confirmed rescan completes and its one-use plan cannot be replayed')
finally:
    request('/auth/logout')
