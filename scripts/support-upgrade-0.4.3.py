#!/usr/bin/python3
"""Supervised, signed 0.3.x -> 0.4.3 support retry with pre-recovery diagnostics.

This performs a real upgrade, including its verified backup and recovery workflow.
It does not delete previous backups, disable signature checks, or change update policy.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

VERSION = '0.4.3'
RELEASE = 'fe7d2f9f-42b7-4274-bb10-daf2307e4e93'
SHA256 = 'afda84a0654dbf65f24fce8a0ad89647cc02211436b09e5f61d92e8c3c02a083'
URL = 'https://zentryc.com/downloads/zenshield/0.4.3/ZenShield-0.4.3.zup'
STATE = Path('/var/lib/zenshield-updater')
CONTROL = Path('/usr/local/lib/zenshield')
SCRIPT_URL = 'https://zentryc.com/downloads/zenshield/diagnostics/support-upgrade-0.4.3-v1.py'


def load_verifier():
    spec = importlib.util.spec_from_file_location('installed_verifier', CONTROL/'ota/package.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def operation(args):
    if args[0] != 'docker':
        return {'rsync':'backup or recovery copy', 'systemctl':'service control',
                'iptables':'maintenance firewall', 'du':'quiesced backup sizing'}.get(args[0], 'host operation')
    if len(args)>1 and args[1]=='load':return 'load signed image'
    if len(args)>1 and args[1]=='compose':
        if 'run' in args:return 'candidate schema verification'
        if 'up' in args:
            return 'dependency startup' if args[-3:]==('postgres','clickhouse','redis') else 'application service startup'
        if 'stop' in args:return 'stop datastore writers'
        if 'exec' in args:return 'application data validation'
    return 'Docker container operation'


def diagnostic_codes(raw):
    # Only static categories leave memory; no raw logs, command text or values.
    patterns = {
        'permission_denied':r'(?i)PermissionError|permission denied|operation not permitted',
        'read_only_filesystem':r'(?i)read-only file system',
        'disk_full':r'(?i)no space left|disk quota exceeded',
        'memory_exhausted':r'(?i)out of memory|cannot allocate memory|oom.?kill|MEMORY_LIMIT_EXCEEDED',
        'connection_refused':r'(?i)connection refused',
        'query_time_limit':r'TIMEOUT_EXCEEDED|TOO_SLOW',
        'connection_timeout':r'(?i)TimeoutError|timed out|timeout expired',
        'authentication_failed':r'(?i)password authentication failed|AuthenticationError|AUTHENTICATION_FAILED|WRONGPASS',
        'missing_database_column':r'UndefinedColumn|UNKNOWN_IDENTIFIER|NO_SUCH_COLUMN_IN_TABLE',
        'missing_database_table':r'UndefinedTable|UNKNOWN_TABLE',
        'duplicate_database_object':r'DuplicateColumn|DuplicateTable|DuplicateObject',
        'database_constraint':r'IntegrityError|UniqueViolation|NotNullViolation|ForeignKeyViolation',
        'encryption_key_mismatch':r'InvalidToken|InvalidSignature',
        'invalid_configuration':r'ValidationError|SettingsError',
        'missing_python_dependency':r'ImportError|ModuleNotFoundError',
        'unsupported_cpu':r'(?i)illegal instruction|invalid opcode',
        'container_runtime_failure':r'(?i)OCI runtime|failed to create task|failed to create shim',
        'port_conflict':r'(?i)address already in use|port is already allocated',
        'missing_file':r'FileNotFoundError|(?i:no such file or directory)',
        'schema_assertion':r'AssertionError',
    }
    result={'categories':sorted(k for k,v in patterns.items() if re.search(v,raw))}
    allowed={'main.py','schema.py','credential.py','config.py','database.py','clickhouse.py',
             'initialize.py','transaction.py','runner.py','env.py','storage_settings.py',
             '002_policy_analytics_aggregates.py','003_correlation_match_evidence.py',
             '004_entity_risk.py','005_syslogs_ingest_time.py','006_forti_utm_events.py',
             '007_typed_analytics_columns.py','008_deferred_analytics_history.py','analytics_backfill.py'}
    result['source_locations'] = sorted({Path(path).name+':'+line for path,line in
        re.findall(r'File "([^"\n]+)", line (\d+)',raw) if Path(path).name in allowed})[:12]
    result['database_error_codes'] = sorted({int(v) for v in re.findall(r'\bCode: (\d{1,5})\b',raw)})[:8]
    known_errors={'MEMORY_LIMIT_EXCEEDED','TIMEOUT_EXCEEDED','TOO_SLOW','UNKNOWN_IDENTIFIER',
                  'UNKNOWN_TABLE','CANNOT_PARSE_TEXT','INCORRECT_DATA','NOT_ENOUGH_SPACE',
                  'TOO_MANY_PARTS','CANNOT_READ_ALL_DATA','CANNOT_OPEN_FILE','ACCESS_DENIED'}
    result['database_error_names'] = sorted(known_errors.intersection(
        re.findall(r'\(([A-Z][A-Z_0-9]{2,60})\)',raw)))[:8]
    return result


def worker(work):
    work=Path(work).resolve()
    if work.parent != (STATE/'support').resolve():raise ValueError('Unexpected support directory')
    archive=work/'package.zup'
    verifier=load_verifier()
    if verifier.digest(archive)!=SHA256:raise ValueError('Support package hash mismatch')
    current=Path('/opt/zensheild/.version').read_text().strip()
    verifier.verify(archive, '/etc/zenshield-updater/release.pub', 'zenai', current, destination=work/'verified')
    sys.path.insert(0,str(CONTROL));sys.path.insert(0,str(work/'verified/code'))
    from ota import common, transaction, runner
    report={'support':'0.4.3-v1','from_version':current,'target_version':VERSION,'failures':[]}
    verified_code=(work/'verified/code').resolve()
    if not all(Path(mod.__file__).resolve().is_relative_to(verified_code) for mod in (common,transaction,runner)):
        raise RuntimeError('Refusing to use an updater outside the verified release')
    if not callable(getattr(transaction,'live_data_size',None)):
        raise RuntimeError('The verified updater is missing the live-storage sizing fix')
    report['updater_bootstrap']='verified_0.4.3_release'
    report['storage_sizing']={'live_scan':'inode_walk','live_roots_scanned':0,'quiesced_du_calls':0}

    previous_attempt=common.read(STATE/'transaction.json',{}).get('attempt_id')
    def save():common.write(work/'report.json',report)
    original_live_size=transaction.live_data_size
    def live_size(path):
        result=original_live_size(path)
        report['storage_sizing']['live_roots_scanned']+=1
        save()
        return result
    transaction.live_data_size=live_size
    original_run=common.run
    original_summary=common.failure_summary
    def details(args, process):
        summary=original_summary(args,process)
        record={'operation':operation(args), 'phase':common.read(STATE/'status.json',{}).get('phase'),
                'exit_code':process.returncode, **diagnostic_codes((process.stdout or '')+'\n'+(process.stderr or ''))}
        record['services']=[]
        report['failures'].append(record);save()
        # Capture candidate failures before recovery recreates their containers.
        for name in ('web','syslog','postgres','clickhouse','redis','nginx'):
            container='zensheild-'+name+'-1'
            try:
                p=subprocess.run(['docker','inspect',container],capture_output=True,text=True,timeout=10)
                if p.returncode:continue
                state=json.loads(p.stdout)[0]['State']
                if state.get('Running') and state.get('Health',{}).get('Status')=='healthy':continue
                logs=subprocess.run(['docker','logs','--tail','150',container],capture_output=True,text=True,timeout=10)
                record['services'].append({'service':name,'running':state.get('Running'),
                    'health':state.get('Health',{}).get('Status'),'exit_code':state.get('ExitCode'),
                    'oom_killed':state.get('OOMKilled'),**diagnostic_codes(logs.stdout+'\n'+logs.stderr)})
            except (OSError,ValueError,KeyError,IndexError,subprocess.TimeoutExpired):
                record['services'].append({'service':name,'diagnostics_unavailable':True})
        save()
        return summary+'; support step: '+record['operation']
    def run(*args,**kwargs):
        if args and args[0]=='du':
            if common.read(STATE/'status.json',{}).get('phase')!='backing_up':
                raise RuntimeError('Refusing a du scan outside quiesced backup preparation')
            writers=subprocess.run(['docker','inspect','--format','{{.State.Running}}',
                *['zensheild-'+name+'-1' for name in transaction.SERVICES]],
                capture_output=True,text=True,timeout=15)
            if writers.returncode or writers.stdout.split()!=['false']*len(transaction.SERVICES):
                raise RuntimeError('Refusing a du scan while datastore writers are running')
            report['storage_sizing']['quiesced_writers_verified']=True
            report['storage_sizing']['quiesced_du_calls']+=1
            save()
        try:return original_run(*args,**kwargs)
        except subprocess.TimeoutExpired:
            report['failures'].append({'operation':operation(args),'categories':['command_timeout']});save()
            raise
    common.failure_summary=details
    common.run=run;transaction.run=run
    save()
    sys.argv=['zenshield-support','apply-file','--file',str(archive),'--sha256',SHA256,'--release-id',RELEASE]
    try:
        runner.main()
    except BaseException as error:
        report['result']='failed'
        report['exception_type']=type(error).__name__
        report['failure_indicators']=diagnostic_codes(common.read(STATE/'status.json',{}).get('message',''))
    else:report['result']='success'
    finally:
        report['installed_version']=common.current_version()
        tx=common.read(STATE/'transaction.json',{})
        if tx.get('to_version')==VERSION and tx.get('attempt_id') and tx['attempt_id']!=previous_attempt:
            report['transaction']={k:tx[k] for k in ('attempt_id','phase','failure_phase','recovery') if k in tx}
        save()
    return 0 if report['result']=='success' else 1


def main():
    if os.geteuid()!=0:raise SystemExit('Run with sudo python3.')
    os.umask(0o077)
    if len(sys.argv)==3 and sys.argv[1]=='--worker':return worker(sys.argv[2])
    current=Path('/opt/zensheild/.version').read_text().strip()
    if current not in ('0.3.3','0.3.4','0.4.0','0.4.1','0.4.2'):
        raise SystemExit('This support command only upgrades older ZenShield appliances to 0.4.3.')
    if shutil.disk_usage(STATE).free<3*1024**3:raise SystemExit('Insufficient space to verify the signed support package.')
    # Holding this lock prevents two copies of this support command from starting.
    import fcntl
    with (STATE/'support.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        unit='zenshield-support-upgrade.service'
        active=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()
        if active in ('active','activating','deactivating'):raise SystemExit('A support upgrade is already running.')
        work=STATE/'support'/uuid.uuid4().hex;work.mkdir(parents=True,mode=0o700)
        print('Preparing a signed support retry. Existing backups will be retained.',flush=True)
        verifier=load_verifier()
        archive=work/'package.zup'
        req=urllib.request.Request(URL,headers={'User-Agent':'zenshield-installer/1'})
        started=time.monotonic()
        with urllib.request.urlopen(req,timeout=30) as response,archive.open('xb') as out:
            for block in iter(lambda:response.read(1024**2),b''):
                if out.tell()+len(block)>600*1024**2 or time.monotonic()-started>1800:raise ValueError('Support download limit exceeded')
                out.write(block)
        if verifier.digest(archive)!=SHA256:raise ValueError('Support package hash mismatch')
        verifier.verify(archive, '/etc/zenshield-updater/release.pub','zenai',current)
        # stdin may be a curl pipe, so persist this exact reviewed public helper for systemd.
        req=urllib.request.Request(SCRIPT_URL,headers={'User-Agent':'zenshield-installer/1'})
        with urllib.request.urlopen(req,timeout=30) as response:source=response.read(128*1024)
        req=urllib.request.Request(SCRIPT_URL+'.sig',headers={'User-Agent':'zenshield-installer/1'})
        with urllib.request.urlopen(req,timeout=30) as response:signature=response.read(65)
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        load_pem_public_key(Path('/etc/zenshield-updater/release.pub').read_bytes()).verify(signature,source)
        helper=work/'worker.py';helper.write_bytes(source)
        subprocess.run(['systemctl','reset-failed',unit],capture_output=True)
        subprocess.run(['systemd-run','--quiet','--no-block','--collect','--unit',unit,'--property=Type=oneshot',
                        '--property=TimeoutStartSec=3600','--property=UMask=0077',
                        '--property=NoNewPrivileges=yes',
                        '/usr/bin/python3',str(helper),'--worker',str(work)],check=True)
    print('Upgrade started under systemd. Services pause during installation; keep the appliance powered on.',flush=True)
    last=None
    for poll in range(1200):
        if (work/'report.json').exists():
            report=json.loads((work/'report.json').read_text())
            if report.get('result'):
                print(json.dumps(report,indent=2),flush=True)
                print('Sanitized report: '+str(work/'report.json'),flush=True)
                return 0 if report['result']=='success' else 1
        if (work/'report.json').exists() and (STATE/'status.json').exists():
            phase=json.loads((STATE/'status.json').read_text()).get('phase')
            if phase!=last:print('Update phase: '+str(phase),flush=True);last=phase
        active=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()
        if poll>4 and active not in ('active','activating'):
            raise SystemExit('Support worker stopped before its final report. Report directory: '+str(work))
        time.sleep(3)
    raise SystemExit('Support upgrade is still running. Keep the appliance powered on; report directory: '+str(work))


if __name__=='__main__':
    sys.exit(main())
