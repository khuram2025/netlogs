#!/usr/bin/python3
"""Build immutable signed v3 packages from prebuilt ZenShield Docker images."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'appliance'))
from ota.package import digest,version,verify

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--version',required=True);p.add_argument('--min-version',required=True)
    p.add_argument('--product-id',required=True);p.add_argument('--private-key',required=True)
    p.add_argument('--public-key',required=True);p.add_argument('--output',required=True)
    p.add_argument('--changelog',required=True);p.add_argument('--source-commit',required=True)
    p.add_argument('--migrations');p.add_argument('--include-control',action='store_true')
    p.add_argument('--image-archive');p.add_argument('--image-id')
    a=p.parse_args();version(a.version);version(a.min_version)
    if version(a.version)<=version(a.min_version):raise SystemExit('Candidate must be newer than minimum version')
    output=Path(a.output)
    if output.exists():raise SystemExit('Immutable output already exists')
    key=load_pem_private_key(Path(a.private_key).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):raise SystemExit('Independent ZenShield Ed25519 key required')
    image='zenshield:'+a.version
    imageid=a.image_id if a.image_archive else subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',image],text=True).strip()
    if a.image_archive and not imageid:raise SystemExit('--image-id is required with --image-archive')
    with tempfile.TemporaryDirectory(prefix='zenshield-release-') as temporary:
        root=Path(temporary);(root/'code').mkdir();(root/'images').mkdir()
        (root/'code/.version').write_text(a.version+'\n')
        if a.image_archive:shutil.copyfile(a.image_archive,root/'images/application.tar')
        else:subprocess.run(['docker','save','-o',str(root/'images/application.tar'),image],check=True)
        ledger=[]
        if a.migrations:
            source=Path(a.migrations);ledger=json.loads((source/'migrations.json').read_text())
            for m in ledger:
                name=Path(m['path'])
                if name.is_absolute() or '..' in name.parts or not name.as_posix().startswith('code/migrations/'):raise SystemExit('Unsafe migration path')
                item=source/name
                if digest(item)!=m['sha256']:raise SystemExit('Migration lock does not match source')
                (root/name).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(item,root/name)
        (root/'code/migrations.json').write_text(json.dumps(ledger,indent=2))
        if a.include_control:
            app=Path(__file__).resolve().parents[1]/'appliance'
            for name in ('agent.py','cli.py','rpc.py','ntp.py'):
                target=root/'code/control'/name;target.parent.mkdir(exist_ok=True);shutil.copyfile(app/'control'/name,target)
            shutil.copyfile(app/'initialize.py',root/'code/initialize.py')
            (root/'code/ota').mkdir()
            for name in ('__init__.py','api.py','common.py','package.py','runner.py','schema.py','transaction.py','transport.py'):
                shutil.copyfile(app/'ota'/name,root/'code/ota'/name)
            shutil.copyfile(app/'ota_entry.py',root/'code/ota_entry.py')
        inventory=''.join(digest(f)+'  '+f.relative_to(root).as_posix()+'\n' for f in sorted(root.rglob('*')) if f.is_file())
        (root/'checksums.sha256').write_bytes(inventory.encode('ascii'))
        manifest={'format_version':3,'recipe':'zenshield-container-v1','update_id':str(uuid.uuid4()),'product_id':a.product_id,
          'version':a.version,'min_version':a.min_version,'arch':'amd64','os_min':'ubuntu-24.04','image':image,'image_id':imageid,
          'release_date':datetime.now(timezone.utc).isoformat(),'severity':'normal','changelog':a.changelog,
          'source_commit':a.source_commit,'inventory_sha256':hashlib.sha256(inventory.encode()).hexdigest()}
        raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
        (root/'manifest.json').write_bytes(raw);(root/'manifest.json.sig').write_bytes(key.sign(raw))
        output.parent.mkdir(parents=True,exist_ok=True)
        with tarfile.open(output,'x:gz') as archive:
            for f in sorted(root.rglob('*')):
                if f.is_file():archive.add(f,arcname=f.relative_to(root).as_posix(),recursive=False)
        verify(output,a.public_key,a.product_id,a.min_version)
        Path(str(output)+'.sha256').write_text(digest(output)+'  '+output.name+'\n')
        print(json.dumps({'package':str(output),'sha256':digest(output),'manifest':manifest},indent=2))

if __name__=='__main__':main()
