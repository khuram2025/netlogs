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
    assert code==200 and b'id="update-dialog"' in page and b'Install now' in page
    assert b'Type INSTALL' not in page and b'id="update-confirmation"' not in page
    print('PASS authenticated live Updates page uses click confirmation')
    assert request('/api/appliance/updates.apply', {'confirmed': True}, csrf=False)[0]==403
    print('PASS live update action requires CSRF protection')
    status=api('updates.status')
    assert status['version']=='0.4.2' and status['registered'] and status['key_installed']
    assert not any(k in status for k in ('api_key','registration_token'))
    api('updates.apply', {'release_id':'stale-release','version':'0.4.1','confirmed':True}, 400)
    api('updates.apply', {'release_id':'stale-release','version':'0.4.2','confirmed':'true'}, 400)
    print('PASS 0.4.2 live status and rejected stale/invalid installation requests')
finally:
    request('/auth/logout')
