#!/usr/bin/python3
"""Rehearse 0.4.1 against private, disposable database copies on the appliance.

Reads production data; never stops or changes production containers/databases.
No customer records, environment values or raw SQL parameters are printed.
"""
import io,json,os,re,secrets,shutil,subprocess,sys,tarfile,tempfile,time,uuid
from pathlib import Path

class CommandFailed(RuntimeError):
    def __init__(self,args,process):
        super().__init__('Command failed: '+args[0]+' '+(args[1] if len(args)>1 else ''))
        self.output=process.stdout+b'\n'+process.stderr

def run(args,**kwargs):
    p=subprocess.run(args,capture_output=True,timeout=kwargs.pop('timeout',120),**kwargs)
    if p.returncode:raise CommandFailed(args,p)
    return p.stdout

def inspect(name):return json.loads(run(['docker','inspect',name]))[0]

def safe_errors(raw,redactions):
    text=raw.decode(errors='replace') if isinstance(raw,bytes) else raw
    for value in sorted(redactions,key=len,reverse=True):
        if len(value)>=5:text=text.replace(value,'[redacted]')
    # Return stack locations and exception summaries, not SQL/parameter dumps.
    lines=[]
    for line in text.splitlines():
        if re.search(r'^\s*File "',line) or re.search(r'^[\w.]+(?:Error|Exception|InvalidToken|UndefinedColumn|UndefinedTable|DuplicateColumn|DuplicateTable):|^ERROR:|^Code: \d+\. DB::Exception:',line):
            line=re.sub(r'(?:https?|postgres(?:ql)?|redis)://\S+','[connection URL]',line)
            line=re.sub(r"'[^']*'", "'[value]'",line)
            line=re.sub(r'\b[A-Za-z0-9_+/=-]{40,}\b','[long value]',line)
            lines.append(line[:500])
    return lines[-32:]

def main():
    if os.geteuid()!=0:raise SystemExit('Run with sudo python3 -')
    image='zenshield:0.4.1'
    info=inspect(image)
    if info['Id']!='sha256:096f681625707513e523d062f6d06c0abc393f1da0e2d33957be901508810340':raise SystemExit('The verified 0.4.1 candidate image is not present; no rehearsal started')
    production={name:inspect('zensheild-'+name+'-1') for name in ('web','postgres','clickhouse','redis')}
    if not all(obj['State']['Running'] for obj in production.values()):raise SystemExit('Production services must already be running')
    if shutil.disk_usage('/var/lib/docker').free<5*1024**3:raise SystemExit('Rehearsal needs 5 GiB free for disposable copies')
    pg_env=dict(value.split('=',1) for value in production['postgres']['Config']['Env'] if '=' in value)
    web_env=dict(value.split('=',1) for value in production['web']['Config']['Env'] if '=' in value)
    redactions=list(pg_env.values())+list(web_env.values())
    pguser=pg_env.get('POSTGRES_USER','zensheild');pgdb=pg_env.get('POSTGRES_DB','zensheild')
    size=int(run(['docker','exec','zensheild-postgres-1','psql','-U',pguser,'-d',pgdb,'-Atc','SELECT pg_database_size(current_database())']).strip())
    if size>512*1024**2:raise SystemExit('PostgreSQL exceeds the bounded rehearsal size; contact support for a larger offline rehearsal')
    # pg_dump uses the local database socket; credentials never enter arguments.
    dump=run(['docker','exec','zensheild-postgres-1','pg_dump','-U',pguser,'-d',pgdb,'--no-owner','--no-privileges'],timeout=180)
    export="""
import json
from fastapi_app.db.clickhouse import ClickHouseClient
c=ClickHouseClient.get_client()
tables=c.query(\"SELECT name,engine FROM system.tables WHERE database=currentDatabase() AND NOT is_temporary ORDER BY engine IN ('View','MaterializedView'),name\").result_rows
ddl=[]
for name,engine in tables:
 if name.startswith('.'):continue
 escaped=name.replace('`','``');ddl.append(c.query('SHOW CREATE TABLE `'+escaped+'`').first_row[0])
ledger=c.query('SELECT id,sha256,ordinal FROM zenshield_ota_migrations ORDER BY ordinal').result_rows if any(n=='zenshield_ota_migrations' for n,e in tables) else []
print(json.dumps({'ddl':ddl,'ledger':ledger}))
"""
    schema=json.loads(run(['docker','exec','-i','zensheild-web-1','python'],input=export.encode()).decode().strip().splitlines()[-1])
    prefix='zs-rehearsal-'+uuid.uuid4().hex[:10];created=[];network=False;report={'rehearsal':'0.4.1-v1','production_unchanged':True}
    phase='prepare copies'
    with tempfile.TemporaryDirectory(prefix='zenshield-rehearsal-',dir='/root') as temporary:
        root=Path(temporary);root.chmod(0o711);credentials=root/'credentials';credentials.mkdir();os.chown(credentials,1000,1000)
        env={'POSTGRES_HOST':prefix+'-pg','POSTGRES_PORT':'5432','POSTGRES_DB':'zensheild','POSTGRES_USER':'zensheild','POSTGRES_PASSWORD':secrets.token_hex(32),'CLICKHOUSE_HOST':prefix+'-ch','CLICKHOUSE_PORT':'8123','CLICKHOUSE_DB':'default','CLICKHOUSE_USER':'zensheild','CLICKHOUSE_PASSWORD':secrets.token_hex(32),'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT':'1','REDIS_URL':'redis://'+prefix+'-redis:6379/0','SECRET_KEY':secrets.token_hex(48),'ZENSHEILD_ADMIN_PASSWORD':secrets.token_hex(32),'WORKERS':'1','ZENSHIELD_APPLIANCE':'1','PYTHONPATH':'/app'}
        redactions.extend(env.values());envfile=root/'environment';envfile.write_text('\n'.join(k+'='+v for k,v in env.items()));envfile.chmod(0o600)
        # Preserve only credential keys in the private copy, never print them.
        source=Path(next(m['Source'] for m in production['web']['Mounts'] if m['Destination']=='/app/data/credentials'))
        for name in ('device-credentials.key','legacy-device-credentials.key'):
            if (source/name).is_file():shutil.copyfile(source/name,credentials/name)
        if not any(credentials.iterdir()):
            archive=run(['docker','cp','zensheild-web-1:/app/fastapi_app/.credential_key','-'])
            with tarfile.open(fileobj=io.BytesIO(archive)) as t:
                files=[m for m in t if m.isfile()];assert len(files)==1 and files[0].size<=128
                (credentials/'legacy-device-credentials.key').write_bytes(t.extractfile(files[0]).read().strip())
        for key in credentials.iterdir():key.chmod(0o600);os.chown(key,1000,1000)
        try:
            run(['docker','network','create','--internal',prefix]);network=True
            for suffix,service,memory in [('pg','postgres','512m'),('ch','clickhouse','2g'),('redis','redis','256m')]:
                name=prefix+'-'+suffix;created.append(name)
                run(['docker','run','-d','--name',name,'--network',prefix,'--env-file',str(envfile),'--memory',memory,production[service]['Image']])
            for _ in range(60):
                pg=subprocess.run(['docker','exec',prefix+'-pg','pg_isready','-h',prefix+'-pg','-U','zensheild'],capture_output=True).returncode==0
                ch=subprocess.run(['docker','exec',prefix+'-ch','wget','-q','-O','-','http://'+prefix+'-ch:8123/ping'],capture_output=True).returncode==0
                if pg and ch:break
                time.sleep(1)
            if not(pg and ch):raise RuntimeError('Disposable database startup timed out')
            phase='restore private database copies'
            run(['docker','exec','-i',prefix+'-pg','psql','-U','zensheild','-d','zensheild','-v','ON_ERROR_STOP=1'],input=dump,timeout=180);del dump
            appargs=['docker','run','--rm','-i','--network',prefix,'--env-file',str(envfile),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','2g','--tmpfs','/tmp:uid=1000,gid=1000,size=256m','--tmpfs','/app/logs:uid=1000,gid=1000','-v',str(credentials)+':/app/data/credentials','--entrypoint','python',image]
            restore="""
import json,sys
from fastapi_app.db.clickhouse import ClickHouseClient
c=ClickHouseClient.get_client();data=json.load(sys.stdin)
for ddl in data['ddl']:c.command(ddl)
if data['ledger']:c.insert('zenshield_ota_migrations',data['ledger'],column_names=['id','sha256','ordinal'])
"""
            run([*appargs,'-c',restore],input=json.dumps(schema).encode())
            phase='OTA schema ledger'
            ledger=Path('/usr/local/lib/zenshield/ota/schema.py').read_text()
            p=subprocess.run([*appargs,'-c',ledger],input=b'[]',capture_output=True,timeout=180)
            if p.returncode:
                report.update(result='failed',phase=phase,errors=safe_errors(p.stdout+p.stderr,redactions));return report
            phase='candidate application startup'
            name=prefix+'-candidate';created.append(name)
            run(['docker','run','-d','--name',name,'--network',prefix,'--env-file',str(envfile),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','3g','--tmpfs','/tmp:size=256m','--tmpfs','/app/logs:uid=1000,gid=1000','-v',str(credentials)+':/app/data/credentials',image])
            healthy=False
            for _ in range(150):
                obj=inspect(name)
                if not obj['State']['Running']:break
                if subprocess.run(['docker','exec',name,'curl','-fsS','http://127.0.0.1:8000/api/health/simple'],capture_output=True).returncode==0:healthy=True;break
                time.sleep(2)
            logs=subprocess.run(['docker','logs','--tail','300',name],capture_output=True)
            report.update(result='passed' if healthy else 'failed',phase=phase,oom_killed=inspect(name)['State'].get('OOMKilled',False),errors=safe_errors(logs.stdout+logs.stderr,redactions))
            return report
        except Exception as e:
            details=safe_errors(getattr(e,'output',b''),redactions)
            report.update(result='failed',phase=phase,errors=details or [type(e).__name__]);return report
        finally:
            for name in reversed(created):subprocess.run(['docker','rm','-f','-v',name],capture_output=True)
            if network:subprocess.run(['docker','network','rm',prefix],capture_output=True)

if __name__=='__main__':
    print('Rehearsing the upgrade in disposable copies. Production services remain running; allow up to five minutes.',flush=True)
    print(json.dumps(main(),indent=2))
