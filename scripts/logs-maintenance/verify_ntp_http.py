"""Measure real authenticated HTTPS responses; never print credentials/cookies."""
from remote import ROOT, connect
import gzip
import http.cookiejar
import json
import re
import ssl
import time
import urllib.parse
import urllib.request

raw = (ROOT / '.env.local').read_text()
pairs = dict(re.findall(r'^\s*([A-Z][A-Z0-9_]*)=(.*)$', raw, re.M))
section = re.split(r'(?im)^.*web.*$', raw, maxsplit=1)[-1]
def credential(key, label):
    value = pairs.get(key)
    if not value:
        match = re.search(r'(?im)^'+label+r'\s*:\s*(.+)$', section)
        value = match.group(1).strip() if match else None
    if not value:
        raise RuntimeError('Missing '+key)
    return value
username = credential('ZENSHIELD_WEB_USERNAME', 'username')
password = credential('ZENSHIELD_WEB_PASSWORD', 'password')
client = connect()
try:
    stdin, stdout, stderr = client.exec_command('sudo -S -p "" docker exec zensheild-nginx-1 cat /etc/nginx/certs/server.crt')
    stdin.write(client._maintenance_password+'\n'); stdin.flush()
    certificate = stdout.read().decode()
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Unable to load appliance public certificate')
finally:
    client.close()
context = ssl.create_default_context(cadata=certificate)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_303 = http_error_302
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                    urllib.request.HTTPCookieProcessor(jar), NoRedirect())
base = 'https://10.10.124.25'
body = urllib.parse.urlencode({'username': username, 'password': password, 'next_url': '/logs/'}).encode()
with opener.open(base+'/auth/login', data=body, timeout=30) as response:
    if response.status != 303:
        raise RuntimeError('Login failed; credentials were not printed')
try:
    import urllib.error
    with opener.open(base+'/system/', timeout=30) as response:
        html=response.read().decode()
        assert response.status == 200
        for marker in ['Time &amp; NTP','ntp-sync','ntp-servers','ntp-retry']:
            assert marker in html, marker
    csrf=next(c.value for c in jar if c.name=='zentryc_csrf')
    def api(op,body):
        req=urllib.request.Request(base+'/api/appliance/'+op,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
        try:
            with opener.open(req,timeout=30) as response:return response.status,json.load(response)
        except urllib.error.HTTPError as response:return response.code,json.load(response)
    code,before=api('time.status',{})
    assert code==200 and isinstance(before['synchronized'],bool), (code,before)
    code,invalid=api('time.update',{'servers':['bad\nallow all']})
    assert code==400, (code,invalid)
    code,after=api('time.status',{})
    assert code==200 and before['servers']==after['servers']
    print(json.dumps({'case':'ntp-system-https','status':200,'panel_present':True,'invalid_server_status':400,'configuration_preserved':True,'synchronized':after['synchronized'],'servers':after['servers'],'service_active':after['service_active'],'peers':after['peers']}))
finally:
    opener.open(base+'/auth/logout',timeout=30).close()
