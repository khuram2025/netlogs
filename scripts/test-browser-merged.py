"""Real Chromium smoke checks of the merged UI on an isolated test database."""
import asyncio,json,logging
from pathlib import Path
from unittest.mock import patch
import uvicorn
from playwright.async_api import async_playwright
from sqlalchemy import select
from fastapi_app import main as web
from fastapi_app.db.database import async_session_maker
from fastapi_app.models.user import User
from fastapi_app.core.auth import create_session_token
logging.getLogger().setLevel(logging.ERROR)
async def main():
 with patch.object(web,'start_scheduler'),patch.object(web,'stop_scheduler'):
  async with web.lifespan(web.app):
   async with async_session_maker() as db:
    user=(await db.execute(select(User).where(User.username=='admin'))).scalar_one()
    token=await create_session_token(user.id,user.username,user.role)
   server=uvicorn.Server(uvicorn.Config(web.app,host='127.0.0.1',port=18000,lifespan='off',log_level='error',access_log=False))
   task=asyncio.create_task(server.serve())
   for _ in range(100):
    if server.started:break
    await asyncio.sleep(.05)
   assert server.started
   try:
    async with async_playwright() as pw:
     browser=await pw.chromium.launch(args=['--no-sandbox','--disable-dev-shm-usage'])
     context=await browser.new_context(viewport={'width':1440,'height':1000})
     await context.add_cookies([{'name':'zentryc_session','value':token,'url':'http://127.0.0.1:18000'}])
     page=await context.new_page();errors=[]
     page.on('pageerror',lambda error:errors.append(str(error)))
     for name,path in [('web-activity','/threats/url-dns/?tab=url'),('windows-dns','/threats/url-dns/?tab=dns'),('log-explorer','/logs/')]:
      await page.goto('http://127.0.0.1:18000'+path,wait_until='networkidle')
      await page.screenshot(path='/test-output/'+name+'.png',full_page=True)
      assert not errors,(name,errors)
      assert await page.locator('body').evaluate('(e)=>e.scrollWidth <= window.innerWidth+2'),name+' overflows viewport'
      print('PASS real Chromium UI',name)
     await page.goto('http://127.0.0.1:18000/auth/logout')
     await browser.close()
   finally:
    server.should_exit=True;await task
asyncio.run(main())
