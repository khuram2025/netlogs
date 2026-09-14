"""Cold, complete datastore backup and recoverable container/host-code switch."""
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
import urllib.request
import yaml
from .common import BASE,STATE,CONTROL,run,compose,write,read,phase,current_version
from .package import digest

HOST_FILES={'code/control/agent.py':CONTROL/'agent.py','code/control/cli.py':CONTROL/'cli.py',
            'code/control/rpc.py':CONTROL/'rpc.py','code/initialize.py':BASE/'initialize.py'}
HOST_FILES.update({'code/ota/'+name:CONTROL/'ota'/name for name in ('__init__.py','api.py','common.py','package.py','runner.py','schema.py','transaction.py','transport.py')})
HOST_FILES['code/ota_entry.py']=CONTROL/'ota_entry.py'
DATA={'clickhouse':('clickhouse','/var/lib/clickhouse'),'postgres':('postgres','/var/lib/postgresql/data'),
      'redis':('redis','/data'),'logs':('web','/app/logs'),'credentials':('web','/app/data/credentials')}
SERVICES=('web','syslog','clickhouse','postgres','redis','nginx')

def maintenance(enable):
    chain='ZENSHIELD-UPDATE'
    if enable:
        subprocess.run(['iptables','-N',chain],capture_output=True)
        run('iptables','-F',chain)
        run('iptables','-A',chain,'-p','tcp','-m','multiport','--dports','80,443','-j','REJECT')
        run('iptables','-A',chain,'-p','udp','--dport','5514','-j','DROP')
        if subprocess.run(['iptables','-C','DOCKER-USER','-j',chain],capture_output=True).returncode:
            run('iptables','-I','DOCKER-USER','1','-j',chain)
        for service in SERVICES:run('docker','update','--restart=no','zensheild-'+service+'-1')
    else:
        if subprocess.run(['iptables','-C','DOCKER-USER','-j',chain],capture_output=True).returncode==0:
            run('iptables','-D','DOCKER-USER','-j',chain)
        for service in SERVICES:run('docker','update','--restart=unless-stopped','zensheild-'+service+'-1')
METRICS='''
import asyncio,json
from sqlalchemy import text
from fastapi_app.db.database import async_session_maker
from fastapi_app.db.clickhouse import ClickHouseClient
async def main():
    async with async_session_maker() as db:
        users=(await db.execute(text('SELECT count(*) FROM users'))).scalar()
    c=ClickHouseClient.get_client()
    assert 'log_time' in {r[0] for r in c.query('DESCRIBE TABLE syslogs').result_rows}
    print(json.dumps({'users':users,'events':c.query('SELECT count() FROM syslogs').first_row[0]}))
asyncio.run(main())
'''

def metrics():return json.loads(compose('exec','-T','web','python','-c',METRICS).splitlines()[-1])

def live_data_size(path):
    """Estimate a changing datastore; only vanished child entries may be skipped.

    ClickHouse removes merge files during traversal. A cold, strict size check
    follows after writers stop; missing roots and all access errors still fail.
    """
    root=Path(path)
    if not root.is_dir():raise ValueError('Appliance data directory is missing')
    size=root.stat().st_size
    def onerror(error):
        if not isinstance(error,FileNotFoundError):raise error
    for directory,dirs,files in os.walk(root,followlinks=False,onerror=onerror):
        for name in dirs+files:
            try:size+=os.stat(os.path.join(directory,name),follow_symlinks=False).st_size
            except FileNotFoundError:continue
    if not root.is_dir():raise ValueError('Appliance data directory disappeared')
    return size

def targets():
    result={}
    for name,(service,destination) in DATA.items():
        obj=json.loads(run('docker','inspect','zensheild-'+service+'-1'))[0]
        mount=next(m for m in obj['Mounts'] if m['Destination']==destination)
        path=Path(mount['Source'])
        if not path.is_absolute() or path.is_symlink():raise ValueError('Unsafe data path')
        actual=str(path.resolve())
        if not (actual.startswith('/var/lib/docker/volumes/zensheild_') or actual.startswith('/srv/zenshield/')):raise ValueError('Unexpected appliance data root')
        result[name]=actual
    if (BASE/'compose.storage.yaml').exists():
        from agent import storage_guard
        storage_guard()
    return result

def health(timeout):
    raw=compose('ps','--format','json');services=json.loads(raw) if raw.startswith('[') else [json.loads(l) for l in raw.splitlines()]
    if len(services)!=6 or not all(s.get('Health')=='healthy' for s in services):raise ValueError('Not all appliance services are healthy')
    ctx=ssl.create_default_context(cafile=str(BASE/'certs/server.crt'))
    with urllib.request.urlopen('https://127.0.0.1/auth/login',context=ctx,timeout=15) as r:
        if b'Zen' not in r.read():raise ValueError('GUI readiness check failed')
    return metrics()

def save_tx(tx):write(STATE/'transaction.json',tx)

def stop(systemd=True):
    if systemd:run('systemctl','stop','zensheild',timeout=180)
    compose('stop',timeout=180)
    for service in ('web','syslog','clickhouse','postgres','redis','nginx'):
        if run('docker','inspect','--format','{{.State.Running}}','zensheild-'+service+'-1')!='false':raise ValueError('A datastore writer is still running')

def start(timeout,systemd=True):
    compose('up','-d','--wait','--wait-timeout',str(timeout),timeout=timeout+45)
    if systemd:run('systemctl','start','zensheild',timeout=timeout+90)

def recover(tx,timeout,systemd=True):
    phase('recovering',release_id=tx['release_id'])
    backup=Path(tx['backup'])
    if not backup.is_relative_to(STATE/'backups') or not (backup/'complete.json').exists():raise ValueError('Transaction backup is not complete')
    metadata=read(backup/'complete.json')
    maintenance(True);stop(systemd)
    current=targets()
    # Resolve current physical paths from Docker; never restore onto a different root.
    if current!=metadata['targets']:raise ValueError('Datastore mount paths changed; recovery requires operator intervention')
    for name,target in current.items():
        run('rsync','-aHAX','--numeric-ids','--delete','--exclude=/lost+found',str(backup/'data'/name)+'/',target+'/',timeout=1800)
        if run('rsync','-aHAXnc','--numeric-ids','--delete','--exclude=/lost+found','--out-format=%n',str(backup/'data'/name)+'/',target+'/',timeout=1800):raise ValueError('Restored data checksum mismatch')
    for name,target in HOST_FILES.items():
        saved=backup/'host'/name
        if saved.exists():shutil.copy2(saved,target)
    if metadata['overlay'] is None:(BASE/'compose.update.yaml').unlink(missing_ok=True)
    else:write(BASE/'compose.update.yaml',metadata['overlay'])
    write(BASE/'.version',metadata['version']+'\n')
    run('systemctl','restart','zenshield-agent',timeout=150)
    start(timeout,systemd)
    after=health(timeout)
    if after['users']<metadata['metrics']['users'] or after['events']<metadata['metrics']['events']:raise ValueError('Restored data validation failed')
    tx['phase']='rolled_back';tx['recovery']='verified';save_tx(tx)
    maintenance(False)

def apply(stage,manifest,offer,timeout):
    stage=Path(stage);tx={'release_id':offer['release_id'],'from_version':current_version(),'to_version':manifest['version'],
       'phase':'preflight','backup':str(STATE/'backups'/manifest['update_id'])}
    # UUID-only directories: signed manifests still have a constrained recipe.
    import uuid
    if str(uuid.UUID(manifest['update_id']))!=manifest['update_id']:raise ValueError('Invalid update ID')
    backup=Path(tx['backup'])
    if backup.exists():raise ValueError('A transaction with this update ID already exists')
    data=targets();before=metrics()
    size=sum(live_data_size(p) for p in data.values())
    if shutil.disk_usage(STATE).free<size*1.25+(stage/'images/application.tar').stat().st_size*2+1024**3:raise ValueError('Insufficient space for complete backup and image staging')
    if Path('/var/lib/zenshield/network-pending.json').exists():raise ValueError('Confirm or revert pending networking before updating')
    import tarfile
    with tarfile.open(stage/'images/application.tar') as saved:
        image_manifest=saved.extractfile('manifest.json')
        content=image_manifest.read(1048577)
        if len(content)>1048576:raise ValueError('Image metadata exceeds limit')
        images=json.loads(content)
        if len(images)!=1 or images[0].get('RepoTags')!=[manifest['image']]:raise ValueError('Image archive must contain only the signed release tag')
    run('docker','load','--input',str(stage/'images/application.tar'),timeout=900)
    if run('docker','image','inspect','--format','{{.Id}}',manifest['image'])!=manifest['image_id']:raise ValueError('Loaded image identity differs from signed manifest')
    metadata={'targets':data,'metrics':before,'version':current_version(),
       'overlay':(BASE/'compose.update.yaml').read_text() if (BASE/'compose.update.yaml').exists() else None,
       'identity_hash':digest(BASE/'.env')}
    tx['phase']='quiescing';save_tx(tx)
    try:
        phase('backing_up',release_id=offer['release_id']);maintenance(True);stop()
        size=sum(int(run('du','-sb',p).split()[0]) for p in data.values())
        if shutil.disk_usage(STATE).free<size*1.25+1024**3:raise ValueError('Insufficient space for complete cold backup')
        backup.mkdir(parents=True,mode=0o700)
        for name,path in data.items():
            destination=backup/'data'/name;destination.mkdir(parents=True)
            run('rsync','-aHAX','--numeric-ids','--exclude=/lost+found',path+'/',str(destination)+'/',timeout=1800)
            if run('rsync','-aHAXnc','--numeric-ids','--exclude=/lost+found','--out-format=%n',path+'/',str(destination)+'/',timeout=1800):raise ValueError('Backup verification failed')
        for name,path in HOST_FILES.items():
            saved=backup/'host'/name;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        run('sync')
        write(backup/'complete.json',metadata)
        tx['phase']='mutating';save_tx(tx);phase('applying',release_id=offer['release_id'])
        for name,path in HOST_FILES.items():
            if (stage/name).exists():shutil.copy2(stage/name,path);path.chmod(0o644)
        overlay={'services':{name:{'restart':'no'} for name in SERVICES}}
        for name in ('web','syslog'):overlay['services'][name].update(image=manifest['image'],pull_policy='never')
        write(BASE/'compose.update.yaml',yaml.safe_dump(overlay))
        run('systemctl','restart','zenshield-agent',timeout=150)
        compose('up','-d','--wait','--wait-timeout',str(timeout),'postgres','clickhouse','redis',timeout=timeout+30)
        ledger=read(stage/'code/migrations.json')
        migrations=[{**m,'sql':(stage/m['path']).read_text()} for m in ledger]
        compose('run','--rm','-T','--no-deps','--entrypoint','python','web','-c',(Path(__file__).parent/'schema.py').read_text(),input=json.dumps(migrations),timeout=600)
        tx['phase']='validating';save_tx(tx);phase('validating',release_id=offer['release_id'])
        start(timeout);after=health(timeout)
        if after['users']<before['users'] or after['events']<before['events'] or digest(BASE/'.env')!=metadata['identity_hash']:raise ValueError('Appliance state did not pass preservation checks')
        write(BASE/'.version',manifest['version']+'\n')
        tx['image']=manifest['image'];tx['phase']='committed';save_tx(tx)
        write(BASE/'compose.update.yaml',yaml.safe_dump({'services':{name:{'image':manifest['image'],'pull_policy':'never'} for name in ('web','syslog')}}))
        maintenance(False)
        return tx
    except BaseException:
        if tx['phase'] in ('mutating','validating'):
            try:recover(tx,timeout)
            except Exception:
                tx['phase']='recovery_failed';save_tx(tx);phase('recovery_failed',message='Recovery needs expert maintenance; backup retained')
                raise RuntimeError('Update failed and recovery requires intervention') from None
        elif tx['phase']!='committed':
            start(timeout);maintenance(False);tx['phase']='aborted';save_tx(tx)
        raise

def recover_incomplete(timeout):
    tx=read(STATE/'transaction.json')
    if not tx:return None
    if tx['phase'] in ('committed','rolled_back','aborted'):
        if tx['phase']=='committed':
            write(BASE/'compose.update.yaml',yaml.safe_dump({'services':{name:{'image':tx['image'],'pull_policy':'never'} for name in ('web','syslog')}}))
        maintenance(False)
        return None if tx.get('reported') else tx
    if tx['phase']=='quiescing':
        start(timeout,False);maintenance(False);tx['phase']='aborted';save_tx(tx)
    else:recover(tx,timeout,False)
    return tx
