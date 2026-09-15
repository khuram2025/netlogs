#!/usr/bin/python3
"""Read-only update diagnostics. Prints no environment values or customer events."""
import datetime,json,os,re,shutil,subprocess
from pathlib import Path

def command(args,timeout=20):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return result.returncode,result.stdout,result.stderr
    except (OSError,subprocess.TimeoutExpired):return -1,'','command unavailable or timed out'

def read_json(path):
    try:return json.loads(Path(path).read_text())
    except (OSError,ValueError):return {}

patterns={
 'out_of_memory':r'(?i)oom[-_ ]kill|out of memory|killed process \d+|cannot allocate memory',
 'disk_full':r'(?i)no space left|disk quota exceeded',
 'permission_denied':r'(?i)permission denied|operation not permitted',
 'cpu_instruction':r'(?i)illegal instruction|invalid opcode',
 'unhealthy':r'(?i)unhealthy|healthcheck failed|health check failed',
 'connection_refused':r'(?i)connection refused',
 'missing_relation':r'UndefinedTable|UndefinedColumn|(?i:does not exist)',
 'duplicate_schema':r'DuplicateTable|DuplicateColumn|DuplicateObject',
 'python_exception':r'\b(?:ImportError|ModuleNotFoundError|SyntaxError|TypeError|AttributeError|ValueError|RuntimeError)\b',
}
def indicators(value):return sorted(name for name,pattern in patterns.items() if re.search(pattern,value))

result={'diagnostic':'zenshield-update-v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True}
base=Path('/opt/zensheild');state=Path('/var/lib/zenshield-updater')
result['installed_version']=(base/'.version').read_text().strip() if (base/'.version').exists() else 'unknown'
for name in ('status','transaction'):
    data=read_json(state/(name+'.json'))
    result[name]={k:data[k] for k in ('phase','from_version','to_version','recovery','reported','failure_phase','updated_at') if k in data}
    if name=='transaction':
        backup=Path(data.get('backup','/nonexistent'))
        if backup.is_relative_to(state/'backups'):
            result[name]['backup_complete']=(backup/'complete.json').is_file()
            saved=read_json(backup/'complete.json')
            result[name]['backup_version']=saved.get('version')
history=[]
for path in sorted((state/'history').glob('*.json'),key=lambda p:p.stat().st_mtime)[-5:]:
    data=read_json(path)
    item={k:data[k] for k in ('from_version','to_version','status','recovery','failure_phase','finished_at') if k in data}
    error=data.get('error','')
    # Legacy updater errors are fixed messages, never command output.
    if re.fullmatch(r'[a-zA-Z0-9 ().;:_/-]{0,250}',error):item['error']=error
    else:item['error_indicators']=indicators(error)
    history.append(item)
result['history']=history
result['cpu_count']=os.cpu_count()
mem={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines()}
result['memory']={k:mem.get(k) for k in ('MemTotal','MemAvailable','SwapTotal','SwapFree')}
cpu=Path('/proc/cpuinfo').read_text()
result['cpu_features']={flag:bool(re.search(r'\b'+flag+r'\b',cpu)) for flag in ('sse4_2','avx','avx2')}
result['filesystems']={}
for path in ('/','/var/lib/docker','/var/lib/zenshield-updater','/srv/zenshield/clickhouse','/srv/zenshield/application'):
    if Path(path).exists():
        usage=shutil.disk_usage(path)
        result['filesystems'][path]={'total_gib':round(usage.total/1024**3,2),'free_gib':round(usage.free/1024**3,2)}
code,out,_=command(['docker','version','--format','{{.Server.Version}}'])
result['docker_version']=out.strip() if not code else 'unavailable'
code,out,_=command(['docker','compose','version','--short'])
result['compose_version']=out.strip() if not code else 'unavailable'
result['services']=[]
for service in ('web','syslog','postgres','clickhouse','redis','nginx'):
    name='zensheild-'+service+'-1'
    code,out,_=command(['docker','inspect',name])
    if code:result['services'].append({'service':service,'missing':True});continue
    obj=json.loads(out)[0];status=obj['State'];host=obj['HostConfig']
    item={'service':service,'image':obj['Config']['Image'],'status':status['Status'],'health':status.get('Health',{}).get('Status'),'exit_code':status.get('ExitCode'),'oom_killed':status.get('OOMKilled'),'memory_limit_mib':host.get('Memory',0)//1024**2,'restart_count':obj.get('RestartCount')}
    health='\n'.join(log.get('Output','') for log in status.get('Health',{}).get('Log',[]))
    code,out,err=command(['docker','logs','--tail','150',name])
    item['log_indicators']=indicators(out+err+health+status.get('Error',''))
    item['exception_classes']=sorted(set(re.findall(r'\b(?:[A-Za-z]+\.)*(?:[A-Za-z]+Error|UndefinedColumn|UndefinedTable|DuplicateColumn|DuplicateTable)\b',out+err)))[:15]
    result['services'].append(item)
for label,args in (
 ('kernel',['journalctl','-k','--since','2026-09-15 05:35:00 UTC','--until','2026-09-15 06:00:00 UTC','--no-pager','-n','250']),
 ('docker',['journalctl','-u','docker','--since','2026-09-15 05:35:00 UTC','--until','2026-09-15 06:00:00 UTC','--no-pager','-n','150']),
):
    code,out,err=command(args);result[label+'_failure_indicators']=indicators(out+err)
sql="SELECT table_name||'.'||column_name||':'||data_type FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('devices','device_credentials','system_settings','llm_providers','alembic_version','users','correlation_rules') ORDER BY table_name,ordinal_position"
code,out,_=command(['docker','exec','zensheild-postgres-1','psql','-U','zensheild','-d','zensheild','-Atc',sql])
result['database_columns']=out.splitlines() if not code else 'unavailable'
print(json.dumps(result,indent=2))
