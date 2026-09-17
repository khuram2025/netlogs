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
    with opener.open(base+'/system/',timeout=30) as response:
        html=response.read().decode()
    script=next(s for s in re.findall(r'<script>(.*?)</script>',html,re.S) if 'function timeFormatter' in s)
    csrf=next(c.value for c in jar if c.name=='zentryc_csrf')
    req=urllib.request.Request(base+'/api/appliance/time.status',data=b'{}',headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
    with opener.open(req,timeout=30) as response:
        status=json.load(response)
    assert status['timezone']=='Asia/Riyadh'
    print(json.dumps({'script':script,'status':status}))
finally:
    opener.open(base+'/auth/logout',timeout=30).close()
