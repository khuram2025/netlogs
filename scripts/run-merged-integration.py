"""Disposable full-source integration fixture. Never uses live appliance databases."""
import json,os,subprocess,sys,tempfile,time,secrets
from pathlib import Path
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
root=Path(__file__).resolve().parent
prefix='zs-merge-test'
image=sys.argv[1]
mode=sys.argv[2] if len(sys.argv)>2 else 'upgrade'
assert mode in ('fresh','upgrade')
run=lambda *a,**kw: subprocess.run(list(a),check=True,**kw)
with tempfile.TemporaryDirectory(prefix='zs-merge-env-',dir='/root') as temporary:
 tmp=Path(temporary);password=secrets.token_urlsafe(32)
 env={'POSTGRES_HOST':prefix+'-pg','POSTGRES_PORT':'5432','POSTGRES_DB':'zensheild','POSTGRES_USER':'zensheild','POSTGRES_PASSWORD':password,'CLICKHOUSE_HOST':prefix+'-ch','CLICKHOUSE_PORT':'8123','CLICKHOUSE_DB':'default','CLICKHOUSE_USER':'zensheild','CLICKHOUSE_PASSWORD':password,'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT':'1','REDIS_URL':'redis://'+prefix+'-redis:6379/0','SECRET_KEY':secrets.token_urlsafe(48),'ZENSHEILD_ADMIN_PASSWORD':secrets.token_urlsafe(24),'PYTHONPATH':'/app','WORKERS':'1','ZENSHIELD_APPLIANCE':'1'}
 e=tmp/'env';e.write_text('\n'.join(k+'='+v for k,v in env.items()));e.chmod(0o600)
 credentials=tmp/'credentials';credentials.mkdir();os.chown(credentials,1000,1000);tmp.chmod(0o711)
 names=[prefix+'-'+x for x in ('pg','ch','redis')]
 try:
  run('docker','network','create',prefix,stdout=subprocess.DEVNULL)
  for name,img,limit in [(names[0],'postgres:16-alpine','512m'),(names[1],'clickhouse/clickhouse-server:25.8-alpine','2g'),(names[2],'valkey/valkey:8-alpine','256m')]:
   run('docker','run','-d','--name',name,'--network',prefix,'--env-file',str(e),'--memory',limit,img,stdout=subprocess.DEVNULL)
  for _ in range(60):
   pg=subprocess.run(['docker','exec',names[0],'pg_isready','-U','zensheild'],capture_output=True).returncode==0
   ch=subprocess.run(['docker','exec',names[1],'wget','-q','-O','-','http://127.0.0.1:8123/ping'],capture_output=True).returncode==0
   if pg and ch:break
   time.sleep(1)
  assert pg and ch,'Fixture databases failed to start'
  def app(img,script):
   run('docker','run','--rm','--network',prefix,'--env-file',str(e),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:uid=1000,gid=1000,size=512m','--tmpfs','/app/logs:uid=1000,gid=1000','-v',str(credentials)+':/app/data/credentials','-v',str(root)+':/tests:ro','--entrypoint','python',img,'/tests/'+script)
  if mode=='upgrade':app('zenshield:0.3.4','seed-merge-baseline.py')
  app(image,'test-merged-appliance.py')
  app(image,'test-dns-integration.py')
  if mode=='fresh':app(image,'benchmark-dns.py')
  print('PASS isolated',mode,'appliance integration')
 finally:
  for n in names:subprocess.run(['docker','rm','-f','-v',n],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','network','rm',prefix],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
