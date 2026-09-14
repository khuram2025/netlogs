import hashlib
import json
from pathlib import Path
import platform
import ssl
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import base64
import secrets
from datetime import datetime,timezone
from .common import STATE,config,current_version,write,read,now
from .package import version

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k):return None

def origin(url):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:raise ValueError('Verified HTTPS URLs are required')
    return parsed.scheme+'://'+parsed.netloc

def ready(c,registered=True):
    origin(c['origin'])
    if not c['contract_confirmed'] or not c['product_id']:raise ValueError('Platform product and API contract are not provisioned')
    if registered and not(c['api_key'] and c['appliance_id']):raise ValueError('Appliance registration is required')

def request(c,route,data=None,event_id=None):
    if not route.startswith('/api/') or route.startswith('//'):raise ValueError('Invalid configured API route')
    url=c['origin'].rstrip('/')+route
    headers={'Content-Type':'application/json','User-Agent':'zenshield-updater/1'}
    if c['api_key']:headers.update(Authorization='Bearer '+c['api_key'])
    if c['appliance_id']:headers['X-Appliance-ID']=c['appliance_id']
    if event_id:headers['Idempotency-Key']=event_id
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=c['ca_file'])),NoRedirect())
    try:
        with opener.open(urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,headers=headers),timeout=30) as response:
            raw=response.read(2*1024*1024+1)
            if len(raw)>2*1024*1024:raise ValueError('OTA response exceeds limit')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:raise ValueError('OTA API returned HTTP '+str(e.code)) from None
    except urllib.error.URLError:raise ValueError('OTA connection or TLS validation failed') from None

def product(c,data):
    value=data.get('product_id',data.get(c['product_field']))
    if value!=c['product_id']:raise ValueError('Server response does not match the provisioned product')

def inventory():return {'hostname':platform.node(),'arch':'amd64','os_version':'ubuntu-24.04','current_version':current_version()}

def register(token):
    from .common import CONFIG
    c=config();ready(c,False)
    if c['api_key']:raise ValueError('Appliance is already registered')
    response=request(c,c['routes']['register'],{**inventory(),'registration_token':token,c['product_field']:c['product_id']})
    product(c,response)
    if not response.get('appliance_id') or not response.get('api_key'):raise ValueError('Incomplete registration response')
    c.update(appliance_id=str(response['appliance_id']),api_key=response['api_key']);write(CONFIG,c)

def offer(c):
    ready(c)
    request(c,c['routes']['checkin'],{**inventory(),c['product_field']:c['product_id']})
    query=urllib.parse.urlencode({'current_version':current_version(),'arch':'amd64',c['product_field']:c['product_id']})
    data=request(c,c['routes']['check']+'?'+query)
    if data.get('available') is not True:
        write(STATE/'offer.json',None);return None
    release=data['release'];product(c,release)
    result={**release,'product_id':c['product_id'],'release_id':str(release.get('release_id',release.get('id',''))),'checked_at':now()}
    if not result['release_id'] or version(result['version'])<=version(current_version()):raise ValueError('Offer is not a newer immutable release')
    if version(current_version())<version(result['min_version']) or result.get('arch')!='amd64':raise ValueError('Offer is incompatible; a bridge release may be required')
    import re
    if not re.fullmatch(r'[0-9a-f]{64}',result.get('package_sha256','')):raise ValueError('Offer is missing a complete SHA256')
    if origin(result['package_url']) not in c['download_origins']:raise ValueError('Untrusted download origin')
    write(STATE/'offer.json',result);return result

def download(c,offer,target):
    # Restart incomplete transfers from byte zero; never append a full 200 response.
    target=Path(target);url=offer['package_url'];started=time.monotonic()
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=c['ca_file'])),NoRedirect())
    for _ in range(4):
        host=origin(url)
        if host not in c['download_origins']:raise ValueError('Untrusted package redirect')
        headers={'User-Agent':'zenshield-updater/1'}
        if host==origin(c['origin']):headers.update({'Authorization':'Bearer '+c['api_key'],'X-Appliance-ID':c['appliance_id']})
        try:response=opener.open(urllib.request.Request(url,headers=headers),timeout=30)
        except urllib.error.HTTPError as e:
            if e.code in (301,302,303,307,308):url=urllib.parse.urljoin(url,e.headers['Location']);continue
            raise ValueError('Package download returned HTTP '+str(e.code)) from None
        with response,target.open('wb') as output:
            size=0;h=hashlib.sha256()
            for chunk in iter(lambda:response.read(1024*1024),b''):
                size+=len(chunk)
                if size>8*1024**3 or time.monotonic()-started>1800:raise ValueError('Package transfer limit exceeded')
                if shutil.disk_usage(target.parent).free<len(chunk)+1024**3:raise ValueError('Insufficient package download space')
                output.write(chunk);h.update(chunk)
            output.flush()
        if h.hexdigest()!=offer['package_sha256']:target.unlink();raise ValueError('Downloaded package hash mismatch')
        return
    raise ValueError('Too many download redirects')

def queue_report(offer,status,old,error='',recovery=None,event=None):
    event=event or str(uuid.uuid4())
    payload={'release_id':offer['release_id'],'status':status,'from_version':old,'to_version':offer['version'],
             'error_message':error,'log_data':json.dumps({'event_id':event,'recovery':recovery})}
    write(STATE/'outbox'/(event+'.json'),payload)
    return event

def flush(c):
    if not c['api_key']:return
    for path in sorted((STATE/'outbox').glob('*.json'),key=lambda p:p.stat().st_mtime_ns):
        try:request(c,c['routes']['report'],read(path),path.stem)
        except Exception:return
        path.unlink()

# Independent licence trust; private signing material exists only on Zentryc.
LICENSE_PUBLIC_KEY = b'''-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAi6FAEf4ugQAyww/eXuPl7QWodvZxuOzRStVJph+kRv8=
-----END PUBLIC KEY-----'''
LICENSE_IDENTITY=STATE/'license-identity.json'
LICENSE_CACHE=STATE/'license.json'
LICENSE_HEALTH=STATE/'license-health.json'

def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def _licence_inventory():
    import ipaddress,subprocess
    try:addresses=[str(ipaddress.ip_address(value)) for value in subprocess.check_output(['hostname','-I'],text=True,timeout=5).split()][:16]
    except (OSError,ValueError,subprocess.SubprocessError):addresses=[]
    return {**inventory(),'management_addresses':addresses}

def _hardware_fingerprint():
    for path in ('/sys/class/dmi/id/product_uuid','/etc/machine-id'):
        try:value=Path(path).read_text().strip().lower()
        except OSError:continue
        if value and set(value)-{'0','-'}:return hashlib.sha256(('ZenShield/v1\n'+value).encode()).hexdigest()
    raise ValueError('A stable appliance identity is required for registration')

def _identity():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    hardware=_hardware_fingerprint()
    if LICENSE_IDENTITY.exists():
        saved=read(LICENSE_IDENTITY)
        if saved['hardware_fingerprint']!=hardware:raise ValueError('This registration identity belongs to another machine. Import a sealed appliance or contact your administrator.')
        key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(saved['private_key'],validate=True))
    else:
        key=Ed25519PrivateKey.generate()
        saved={'hardware_fingerprint':hardware,'private_key':base64.b64encode(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode()}
        write(LICENSE_IDENTITY,saved)
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return key,base64.b64encode(raw).decode(),hashlib.sha256(raw).hexdigest(),hardware

def _verify_licence(envelope,appliance_id,key_fingerprint,nonce=None):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        payload=envelope['payload']
        load_pem_public_key(LICENSE_PUBLIC_KEY).verify(base64.b64decode(envelope['signature'],validate=True),_canonical(payload))
        if payload['format']!=1 or payload['product_id']!='zenai' or payload['appliance_id']!=appliance_id or payload['key_fingerprint']!=key_fingerprint:raise ValueError()
        if payload['hardware_fingerprint']!=_hardware_fingerprint():raise ValueError()
        if nonce is not None and payload['request_nonce']!=nonce:raise ValueError()
        datetime.fromisoformat(payload['issued_at']);datetime.fromisoformat(payload['refresh_by'])
        if payload['licence']['expires_at']:datetime.fromisoformat(payload['licence']['expires_at'])
    except Exception:raise ValueError('Licence signature or appliance binding is invalid') from None
    return payload

def _enroll_identity(c,identity):
    from .common import CONFIG
    key,public,fingerprint,hardware=identity
    body={**_licence_inventory(),'product':'zenai','public_key':public,'hardware_fingerprint':hardware}
    try:challenge=request(c,'/api/v1/zenshield/registration/challenge',body)
    except ValueError:
        if not c.get('api_key'):raise
        # A previous response can be lost after the server rotated the credential.
        # Proof of the persisted private identity recovers the same registration.
        challenge=request({**c,'api_key':'','appliance_id':''},'/api/v1/zenshield/registration/challenge',body)
    product(c,challenge)
    try:
        message=base64.b64decode(challenge['message'],validate=True);proof=json.loads(message)
        if len(message)>2048 or proof!={'purpose':'zenshield-enrollment-v1','challenge_id':challenge['challenge_id'],'nonce':proof['nonce'],'public_key':public,'hardware_fingerprint':hardware}:raise ValueError()
        if not isinstance(proof['nonce'],str) or len(proof['nonce'])!=64:raise ValueError()
    except Exception:raise ValueError('Invalid registration challenge') from None
    nonce=secrets.token_hex(32)
    response=request({**c,'api_key':'','appliance_id':''},'/api/v1/zenshield/registration/complete',{
        'challenge_id':challenge['challenge_id'],'signature':base64.b64encode(key.sign(message)).decode(),'nonce':nonce})
    product(c,response)
    appliance_id=str(response.get('appliance_id',''));api_key=response.get('api_key','')
    if not appliance_id or not isinstance(api_key,str) or len(api_key)!=64:raise ValueError('Incomplete appliance registration')
    _verify_licence(response['licence'],appliance_id,fingerprint,nonce)
    c.update(appliance_id=appliance_id,api_key=api_key);write(CONFIG,c)
    write(LICENSE_CACHE,response['licence'])
    return response['licence']

def sync_licence(registration_code=None):
    from .common import locked
    with locked(STATE/'license.lock'),locked(STATE/'update.lock'):
        c=config();ready(c,False)
        identity=_identity();nonce=secrets.token_hex(32)
        if not c.get('api_key') or not LICENSE_CACHE.exists():_enroll_identity(c,identity)
        route='/api/v1/zenshield/licence/claim' if registration_code else '/api/v1/zenshield/licence'
        body={**_licence_inventory(),'nonce':nonce}
        if registration_code:body['registration_token']=registration_code
        response=request(c,route,body);product(c,response)
        _verify_licence(response['licence'],c['appliance_id'],identity[2],nonce)
        write(LICENSE_CACHE,response['licence']);write(LICENSE_HEALTH,{'last_sync':now(),'error':None})
    return licence_status()

def licence_status():
    c=config();health=read(LICENSE_HEALTH,{})
    result={'registered':bool(c.get('api_key') and c.get('appliance_id')),'appliance_id':c.get('appliance_id') or None,
        'status':'registration_pending','licence':None,'last_sync':health.get('last_sync'),'sync_error':health.get('error'),
        'refresh_interval_seconds':300,'portal_url':'https://zentryc.com/ota/fleet/?tab=subscriptions'}
    if not LICENSE_CACHE.exists():return result
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        saved=read(LICENSE_IDENTITY)
        key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(saved['private_key'],validate=True))
        fingerprint=hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest()
        payload=_verify_licence(read(LICENSE_CACHE),c['appliance_id'],fingerprint)
        licence=dict(payload['licence']);at=datetime.now(timezone.utc)
        # Signed server time is a floor; clock rollback cannot restore an expired snapshot.
        at=max(at,datetime.fromisoformat(payload['issued_at']))
        if licence['status'] in ('active','trial') and licence['expires_at'] and datetime.fromisoformat(licence['expires_at'])<=at:licence['status']='expired'
        licence['days_remaining']=max(0,__import__('math').ceil((datetime.fromisoformat(licence['expires_at'])-at).total_seconds()/86400)) if licence['expires_at'] else None
        result.update(status=licence['status'],licence=licence,verified=True,stale=at>datetime.fromisoformat(payload['refresh_by']),revision=payload['revision'])
    except Exception:result.update(status='verification_failed',verified=False,sync_error='The cached licence cannot be verified. Refresh the licence or contact support.')
    return result

def licence_background():
    time.sleep(5)
    while True:
        if Path('/var/lib/zenshield/setup-complete').exists():
            try:sync_licence()
            except Exception:
                try:
                    prior=read(LICENSE_HEALTH,{})
                    write(LICENSE_HEALTH,{'last_sync':prior.get('last_sync'),'error':'Licence synchronization is pending. Check connectivity to Zentryc or use Refresh licence for details.'})
                except OSError:pass
        time.sleep(300)
