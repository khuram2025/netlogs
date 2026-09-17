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
    for label, params in [('reported-range', {'srcip':'10.10.190.12-10.10.193.13','action':'deny','scope':'internet','time_range':'1h'}),
                          ('reported', {'q':'srcip:172.20.30.46','action':'deny','scope':'internet','time_range':'7d'}),
                          ('one-minute', {'time_range':'1m'}),
                          ('tcp-443', {'protocol':'TCP','dstport':'443','action':'accept','time_range':'7d'})]:
        params.update(page='1', per_page='100', group_by='srcip,dstip,dstport')
        request = urllib.request.Request(base+'/logs/?'+urllib.parse.urlencode(params), headers={'Accept-Encoding':'gzip'})
        start = time.perf_counter()
        with opener.open(request, timeout=45) as response:
            data = response.read()
            html = gzip.decompress(data) if response.headers.get('Content-Encoding') == 'gzip' else data
            status = re.search(rb'id="nqlStatus"[^>]*>(.*?)</span>', html)
            if label == 'reported-range':
                import ipaddress
                cells = re.findall(rb'<td data-col="srcip">(.*?)</td>', html, re.S)
                ips = [re.search(rb'>([0-9.]+)</a>', cell).group(1).decode() for cell in cells]
                assert ips and all(ipaddress.ip_address('10.10.190.12') <= ipaddress.ip_address(ip) <= ipaddress.ip_address('10.10.193.13') for ip in ips)
                assert b'Filter timezone: <strong>UTC</strong>' in html
                print(json.dumps({'case':'range-https-correctness','rows':len(ips),'all_ips_in_range':True,'timezone_label_present':True}),flush=True)
            print(json.dumps({'case':label, 'https_seconds':round(time.perf_counter()-start,3),
                              'status':response.status, 'encoding':response.headers.get('Content-Encoding'),
                              'wire_bytes':len(data), 'html_bytes':len(html),
                              'query_status':status.group(1).decode() if status else None}), flush=True)
finally:
    # Revoke only this script's session; the user's browser session is separate.
    opener.open(base+'/auth/logout', timeout=30).close()
