"""Run old/new appliance services with native named volumes and pinned dependencies.

Isolated Compose project; no host ports, management socket or production data.
"""
import io,json,os,secrets,shutil,subprocess,sys,tarfile,tempfile
from pathlib import Path
import yaml
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
root=Path(__file__).resolve().parents[1]
candidate=sys.argv[1] if len(sys.argv)>1 else 'zenshield:0.4.1'
project='zs-system-upgrade-test'
assert not subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).strip()
pins={'postgres':'postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685','clickhouse':'clickhouse/clickhouse-server@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146','redis':'valkey/valkey@sha256:d2e18f3410b6f616de1417f570fa55261af2898b9c5b2cfb6781ce2373ea43d1','nginx':'nginx@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c'}
with tempfile.TemporaryDirectory(prefix='zs-system-upgrade-',dir='/root') as temporary:
    temp=Path(temporary)
    env={k:secrets.token_hex(32) for k in ('SECRET_KEY','ZENSHEILD_ADMIN_PASSWORD','POSTGRES_PASSWORD','CLICKHOUSE_PASSWORD','REDIS_PASSWORD')}
    (temp/'.env').write_text('\n'.join(k+'='+v for k,v in env.items()));(temp/'.env').chmod(0o600)
    config=yaml.safe_load((root/'appliance/compose.yaml').read_text());config['name']=project
    for name,service in config['services'].items():
        service.pop('build',None);service.pop('ports',None);service['restart']='no'
        service['image']=pins.get(name,'zenshield:0.3.4');service['pull_policy']='never'
        service['volumes']=[v for v in service.get('volumes',[]) if not v.startswith('/run/zenshield:')]
    composefile=temp/'compose.yaml';composefile.write_text(yaml.safe_dump(config))
    shutil.copyfile(root/'appliance/nginx.conf',temp/'nginx.conf');(temp/'certs').mkdir()
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(temp/'certs/server.key'),'-out',str(temp/'certs/server.crt'),'-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def clean(value):
        for secret in env.values():value=value.replace(secret,'[redacted]')
        return value
    def run(*args,**kwargs):
        p=subprocess.run(args,capture_output=True,text=True,timeout=kwargs.pop('timeout',420),**kwargs)
        if p.returncode:
            print(clean(p.stdout[-3000:]+'\n'+p.stderr[-7000:]),flush=True)
            raise RuntimeError('Isolated service command failed: '+args[0])
        return p.stdout
    def compose(*args,**kwargs):return run('docker','compose','-p',project,'-f',str(composefile),*args,**kwargs)
    try:
        print('Starting real 0.3.4 native-volume fixture',flush=True)
        compose('up','-d','--wait','--wait-timeout','300')
        print('PASS six baseline services healthy with native Docker volumes',flush=True)
        if '--populated' in sys.argv:
            seed = """
from fastapi_app.db.clickhouse import ClickHouseClient
c=ClickHouseClient.get_client()
c.command(\"INSERT INTO syslogs (timestamp,device_ip,facility,severity,srcip,dstip,dstport,proto,action,policyname,message,raw,log_type,parsed_data) SELECT now()-toIntervalDay(number%40),toIPv4('198.18.0.10'),1,6,concat('10.0.',toString(intDiv(number%65000,250)),'.',toString(number%250)), '198.18.1.1',443,6,if(number%2=0,'deny','accept'),if(number%3=0,'','fixture-policy'),'migration-fixture','migration-fixture',if(number%10=0,'utm/ips','traffic'),map('level','warning','attack','fixture') FROM numbers(100000)\",settings={'async_insert':0})
print('PASS populated historical policy, deny, flow and IPS migration fixture')
"""
            print(compose('exec','-T','web','python','-c',seed).strip(),flush=True)
        if '--rehearse' in sys.argv:
            import importlib.util
            spec=importlib.util.spec_from_file_location('rehearsal',root/'scripts/rehearse-update.py')
            rehearsal=importlib.util.module_from_spec(spec);spec.loader.exec_module(rehearsal)
            original=rehearsal.run
            def remapped(args,**kwargs):
                mapped=[project+value[len('zensheild'):] if isinstance(value,str) and value.startswith('zensheild-') else value for value in args]
                return original(mapped,**kwargs)
            rehearsal.run=remapped
            result=rehearsal.main();print(json.dumps(result),flush=True)
            assert result['result']=='passed','Old-version private-copy rehearsal failed'
        web=project+'-web-1'
        # Exercise exactly the host's legacy-key preservation before replacement.
        obj=json.loads(run('docker','inspect',web))[0]
        volume=Path(next(m['Source'] for m in obj['Mounts'] if m['Destination']=='/app/data/credentials'))
        assert volume.is_relative_to('/var/lib/docker/volumes/'+project+'_app-credentials')
        raw=subprocess.check_output(['docker','cp',web+':/app/fastapi_app/.credential_key','-'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            member=next(m for m in t if m.isfile());key=t.extractfile(member).read().strip()
        saved=volume/'legacy-device-credentials.key';saved.write_bytes(key);saved.chmod(0o600);os.chown(saved,1000,1000)
        compose('stop')
        for name in ('web','syslog'):config['services'][name]['image']=candidate
        composefile.write_text(yaml.safe_dump(config))
        compose('up','-d','--wait','--wait-timeout','300','postgres','clickhouse','redis')
        compose('run','--rm','-T','--no-deps','--entrypoint','python','web','-c',(root/'appliance/ota/schema.py').read_text(),input='[]')
        print('PASS candidate OTA SQL ledger preflight',flush=True)
        compose('up','-d','--wait','--wait-timeout','300')
        print('PASS six candidate services healthy after native-volume upgrade',flush=True)
        if '--populated' in sys.argv:
            validate="""
import json
from fastapi_app.db.clickhouse import ClickHouseClient
c=ClickHouseClient.get_client()
counts={table:c.query('SELECT count() FROM '+table).first_row[0] for table in ('syslogs','forti_utm_events')}
for table in ('policy_hits_daily','implicit_deny_daily','flow_pairs_daily'):
 counts[table]=c.query('SELECT sum(hits) FROM '+table).first_row[0]
assert counts['syslogs']==100000,counts
assert counts['flow_pairs_daily']==counts['syslogs'],counts
assert counts['policy_hits_daily']>0 and counts['implicit_deny_daily']>0 and counts['forti_utm_events']>0,counts
print('PASS populated migration backfill counts '+json.dumps(counts))
"""
            print(compose('exec','-T','web','python','-c',validate).strip(),flush=True)
        assert (volume/'device-credentials.key').is_file() and not saved.exists()
        print('PASS legacy credential key rotated on native Docker volume',flush=True)
    except Exception:
        for service in ('web','syslog','postgres','clickhouse'):
            p=subprocess.run(['docker','logs','--tail','100',project+'-'+service+'-1'],capture_output=True,text=True)
            print(service+': '+clean(p.stdout[-1500:]+'\n'+p.stderr[-6500:]),flush=True)
        raise
    finally:
        subprocess.run(['docker','compose','-p',project,'-f',str(composefile),'down','-v','--remove-orphans'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
