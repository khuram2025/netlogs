"""Strict signed-package verification. No archive content executes here."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import shutil
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class InvalidPackage(ValueError): pass

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}',value):
        raise InvalidPackage('Expected an X.Y.Z version')
    return tuple(map(int,value.split('.')))

def load_json(raw):
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise InvalidPackage('Duplicate JSON key')
            result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs)

def verify(package,public_key,product,current,offer=None,destination=None,max_age=180):
    package=Path(package)
    if package.stat().st_size>8*1024**3:raise InvalidPackage('Archive exceeds 8 GiB')
    if offer and digest(package)!=offer['package_sha256']:raise InvalidPackage('Archive SHA256 does not match the offer')
    with tarfile.open(package,'r:gz') as archive:
        members={};expanded=0
        for item in archive:
            path=PurePosixPath(item.name)
            if not item.isfile() or path.is_absolute() or '..' in path.parts or '\\' in item.name or str(path)!=item.name or item.name in members:
                raise InvalidPackage('Unsafe or duplicate archive member')
            if len(item.name)>240 or item.size<0:raise InvalidPackage('Invalid archive member')
            expanded+=item.size
            if expanded>16*1024**3 or len(members)>=10000:raise InvalidPackage('Archive expansion limit exceeded')
            members[item.name]=item
        for name,limit in [('manifest.json',262144),('manifest.json.sig',64),('checksums.sha256',1048576)]:
            if name not in members or members[name].size>limit:raise InvalidPackage('Missing or oversized metadata')
        manifest_bytes=archive.extractfile(members['manifest.json']).read()
        signature=archive.extractfile(members['manifest.json.sig']).read()
        key=load_pem_public_key(Path(public_key).read_bytes())
        if not isinstance(key,Ed25519PublicKey):raise InvalidPackage('Ed25519 verification key required')
        try:key.verify(signature,manifest_bytes)
        except Exception:raise InvalidPackage('Release signature is invalid') from None
        m=load_json(manifest_bytes)
        if m.get('format_version')!=3 or m.get('recipe')!='zenshield-container-v1':raise InvalidPackage('Unsupported release contract')
        if not product or m.get('product_id')!=product:raise InvalidPackage('Wrong product identity')
        if m.get('arch')!='amd64' or m.get('os_min')!='ubuntu-24.04':raise InvalidPackage('Unsupported release target')
        if version(m['version'])<=version(current):raise InvalidPackage('Same-version installation or downgrade refused')
        if version(current)<version(m['min_version']):raise InvalidPackage('A bridge release is required')
        if m.get('image')!='zenshield:'+m['version'] or not re.fullmatch(r'sha256:[0-9a-f]{64}',m.get('image_id','')):raise InvalidPackage('Invalid image identity')
        date=datetime.fromisoformat(m['release_date'].replace('Z','+00:00'))
        if date.tzinfo is None:raise InvalidPackage('Release timestamp needs a timezone')
        age=(datetime.now(timezone.utc)-date).total_seconds()
        if age< -86400 or age>max_age*86400:raise InvalidPackage('Release date outside the configured trust window')
        if offer:
            for field in ('version','product_id','arch','min_version'):
                if m[field]!=offer[field]:raise InvalidPackage('Offer and signed manifest disagree: '+field)
        inventory_bytes=archive.extractfile(members['checksums.sha256']).read()
        if hashlib.sha256(inventory_bytes).hexdigest()!=m.get('inventory_sha256'):raise InvalidPackage('Checksum inventory is not bound to the signature')
        inventory={}
        for line in inventory_bytes.decode('ascii').splitlines():
            if not re.fullmatch(r'[0-9a-f]{64}  [A-Za-z0-9_./-]+',line):raise InvalidPackage('Invalid checksum inventory')
            checksum,name=line.split('  ',1)
            if name in inventory:raise InvalidPackage('Duplicate checksum entry')
            inventory[name]=checksum
        payload=set(members)-{'manifest.json','manifest.json.sig','checksums.sha256'}
        if payload!=set(inventory):raise InvalidPackage('Unexpected or missing payload content')
        fixed={'code/.version','code/migrations.json','images/application.tar'}
        host={'code/control/agent.py','code/control/cli.py','code/control/rpc.py','code/initialize.py'}
        host|={'code/ota/'+name for name in ('__init__.py','api.py','common.py','package.py','runner.py','schema.py','transaction.py','transport.py')}
        host.add('code/ota_entry.py')
        for name in payload-fixed-host:
            if not re.fullmatch(r'code/migrations/(postgres|clickhouse)/[A-Za-z0-9_-]+\.sql',name):raise InvalidPackage('Payload root is not allowed')
        if not fixed<=payload:raise InvalidPackage('Incomplete release payload')
        for name in payload:
            limit=128 if name=='code/.version' else 5*1024**2
            if name!='images/application.tar' and members[name].size>limit:raise InvalidPackage('Code or migration metadata exceeds limit')
        for name,checksum in inventory.items():
            h=hashlib.sha256()
            with archive.extractfile(members[name]) as source:
                for block in iter(lambda:source.read(1024*1024),b''):h.update(block)
            if h.hexdigest()!=checksum:raise InvalidPackage('Payload hash mismatch: '+name)
        if archive.extractfile(members['code/.version']).read().decode().strip()!=m['version']:raise InvalidPackage('Version file mismatch')
        migrations=load_json(archive.extractfile(members['code/migrations.json']).read())
        if not isinstance(migrations,list):raise InvalidPackage('Migration ledger must be an ordered list')
        seen=set()
        for migration in migrations:
            name=migration['path']
            if name in seen or not re.fullmatch(r'code/migrations/(postgres|clickhouse)/[A-Za-z0-9_-]+\.sql',name) or inventory.get(name)!=migration['sha256']:
                raise InvalidPackage('Invalid complete migration ledger')
            seen.add(name)
        if seen!={n for n in payload if n.startswith('code/migrations/')}:raise InvalidPackage('Untracked migration payload')
        if destination:
            destination=Path(destination)
            if shutil.disk_usage(destination.parent).free<expanded+1024**3:raise InvalidPackage('Insufficient space to stage the verified release')
            destination.mkdir(mode=0o700,parents=True,exist_ok=False)
            # All names/types/hashes were checked before creating payload files.
            for name,item in members.items():
                target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
                with archive.extractfile(item) as source,target.open('xb') as out:
                    for block in iter(lambda:source.read(1024*1024),b''):out.write(block)
                target.chmod(0o600)
        return m
