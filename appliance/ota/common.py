import fcntl
import json
import os
from pathlib import Path
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone

BASE=Path('/opt/zensheild')
STATE=Path('/var/lib/zenshield-updater')
CONFIG=Path('/etc/zenshield-updater/config.json')
PUBLIC_KEY=Path('/etc/zenshield-updater/release.pub')
CONTROL=Path('/usr/local/lib/zenshield')
DEFAULT={'portal_url':'https://zentryc.com/ota/zenai/releases/','origin':'https://zentryc.com',
 'product_id':'zenai','contract_confirmed':False,'product_field':'product',
 'routes':{'register':'/api/v1/appliances/register','checkin':'/api/v1/appliances/checkin','check':'/api/v1/updates/check','report':'/api/v1/updates/report'},
 'download_origins':['https://zentryc.com'],'auto_update':False,'window_start':'02:00','window_end':'04:00',
 'max_manifest_age_days':180,'health_timeout':300,'appliance_id':'','api_key':'','ca_file':None}

def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.new')
    with temp.open('w') as f:
        os.chmod(temp,0o600);f.write(value if isinstance(value,str) else json.dumps(value,indent=2));f.flush();os.fsync(f.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read(path,default=None):return json.loads(Path(path).read_text()) if Path(path).exists() else default
def config():return {**DEFAULT,**read(CONFIG,{})}
def current_version():return (BASE/'.version').read_text().strip() if (BASE/'.version').exists() else '0.2.0'
def now():return datetime.now(timezone.utc).isoformat()

def run(*args,timeout=600,input=None):
    p=subprocess.run(args,text=True,input=input,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError(Path(args[0]).name+' failed (exit '+str(p.returncode)+')')
    return p.stdout.strip()

def compose(*args,timeout=600,input=None):
    command=['docker','compose','--project-directory',str(BASE),'-f',str(BASE/'compose.yaml')]
    for overlay in ('compose.storage.yaml','compose.update.yaml'):
        if (BASE/overlay).exists():command+=['-f',str(BASE/overlay)]
    return run(*command,*args,timeout=timeout,input=input)

@contextmanager
def locked(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another appliance operation is running')
        yield

def phase(name,**details):
    write(STATE/'status.json',{'phase':name,'updated_at':now(),**details})

def window_open(c,at=None):
    from datetime import time
    start=time.fromisoformat(c['window_start']);end=time.fromisoformat(c['window_end'])
    value=(at or datetime.now(timezone.utc)).time().replace(tzinfo=None)
    if start==end:return False
    return start<=value<end if start<end else value>=start or value<end
