"""Browser regression for the real Updates template with controlled API responses."""
import json,re
from pathlib import Path
from playwright.sync_api import sync_playwright

root=Path(__file__).resolve().parents[1]
html=(root/'fastapi_app/templates/system/appliance.html').read_text()
assert html==(root/'appliance/control/system.html').read_text()
html=re.sub(r'{%.*?%}','',html,flags=re.S)
state={'hostname':'test','interfaces':[],'routes':[],'dns':'','uptime_seconds':60,'timezone':'UTC','services':'[]','network_pending':None}
pool={'pool':None,'volumes':[],'jobs':[],'disks':[],'managed':False}
updates={'version':'0.3.4','status':{'phase':'available'},'provisioned':True,'registered':True,'key_installed':True,'auto_update':False,'window_start':'02:00','window_end':'04:00','pending_reports':0,'offer':{'release_id':'release-test','version':'0.4.2','changelog':'Update recovery improvements'},'history':[{'from_version':'0.3.4','to_version':'0.4.1','status':'failed','recovery':'verified','error':'Docker migration failed','finished_at':'2026-09-15T05:44:27Z'}]}
submitted=[];errors=[]
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
    page=browser.new_page(viewport={'width':1440,'height':1000})
    page.on('pageerror',lambda e:errors.append(str(e)))
    def route(request):
        url=request.request.url
        if '/api/appliance/' not in url:
            request.fulfill(status=200,content_type='text/html',body=html);return
        op=url.rsplit('/',1)[-1]
        responses={'status':state,'storage':pool,'updates.status':updates,'licences.status':{'status':'trial','registered':True,'licence':None}}
        if op=='updates.apply':
            submitted.append(request.request.post_data_json)
            response={'message':'Update installation queued'}
        else:response=responses.get(op,{})
        request.fulfill(status=200,content_type='application/json',body=json.dumps(response))
    page.route('**/*',route)
    page.goto('http://zenshield.test/system/#updates')
    page.wait_for_function("!document.getElementById('update-install').disabled")
    assert page.locator('#update-confirmation').count()==0
    assert 'Docker migration failed' in page.locator('#update-history').inner_text()
    page.locator('#update-install').click()
    assert page.locator('#update-dialog').is_visible() and not submitted
    assert '0.4.2' in page.locator('#update-dialog-title').inner_text()
    page.locator('#cancel-update').click();assert not submitted
    page.locator('#update-install').click();page.locator('#confirm-update').click()
    page.wait_for_function("document.getElementById('message').textContent==='Update installation queued'")
    assert submitted==[{'release_id':'release-test','version':'0.4.2','confirmed':True}]
    assert not page.locator('#update-dialog').is_visible()
    assert not errors,errors
    browser.close()
print('PASS Updates UI: no typed phrase, explicit version confirmation, cancel sends nothing, one confirmed request, failure reason visible, no JavaScript errors')
