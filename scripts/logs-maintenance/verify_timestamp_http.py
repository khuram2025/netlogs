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
    from html import unescape
    params={'page':'1','time_range':'1m','per_page':'100','group_by':'srcip,dstip,dstport'}
    start=time.perf_counter()
    with opener.open(base+'/logs/?'+urllib.parse.urlencode(params),timeout=30) as response:
        html=response.read().decode()
        assert response.status==200
    seconds=round(time.perf_counter()-start,3)
    rows=re.findall(r'<tr class="log-row".*?<td data-col="timestamp">(.*?)</td>.*?<tr class="detail-row"(.*?)>',html,re.S)
    assert len(rows)==100, len(rows)
    examples=[]
    for idx in [0,49,99]:
        cell,attrs=rows[idx]
        shown=unescape(re.search(r'<span[^>]*>(.*?)</span>',cell,re.S).group(1)).strip()
        meta=dict(re.findall(r'data-([a-z]+)="([^"]*)"',attrs))
        query={k:unescape(meta[k]) for k in ['timestamp','device','srcip','dstip','srcport','dstport','proto'] if meta.get(k)}
        with opener.open(base+'/api/logs/detail?'+urllib.parse.urlencode(query),timeout=30) as response:
            data=json.load(response)
        pd=data['parsed_data']
        expected=pd.get('log_datetime') or pd.get('date','')+' '+pd.get('time','')
        assert shown==expected, (shown,expected)
        raw=data.get('raw','')
        if pd.get('date') and pd.get('time'):
            assert pd['date'] in raw and pd['time'] in raw
        with opener.open(base+'/logs/detail-panel?'+urllib.parse.urlencode(query),timeout=30) as response:
            panel=response.read().decode()
            assert 'Normalized (UTC)' in panel and expected in panel
        examples.append({'row':idx+1,'shown':shown,'source_offset':pd.get('tz'),'normalized':query['timestamp'],'matches_raw':True})
    print(json.dumps({'case':'live-device-timestamp','rows':len(rows),'seconds':seconds,'samples':examples}))
finally:
    opener.open(base+'/auth/logout',timeout=30).close()
