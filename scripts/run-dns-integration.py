"""Launch DNS tests with the disposable web container's configuration, without exposing secrets."""
import json,subprocess,tempfile,os,sys
from pathlib import Path
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
env=json.loads(subprocess.check_output(['docker','inspect','zensheild-web-1']))[0]['Config']['Env']
fd,name=tempfile.mkstemp(prefix='dns-test-env-',dir='/root')
try:
 with os.fdopen(fd,'w') as f:f.write('\n'.join(env)+'\nPYTHONPATH=/app\n')
 test=sys.argv[2] if len(sys.argv)>2 else 'test-dns-integration.py'
 assert test in ('test-dns-integration.py','benchmark-dns.py')
 result=subprocess.run(['docker','run','--rm','--network','zensheild_backend','--env-file',name,'-v',str(Path(__file__).with_name(test))+':/tmp/test-dns-integration.py:ro','--entrypoint','python',sys.argv[1],'/tmp/test-dns-integration.py'])
finally:os.unlink(name)
sys.exit(result.returncode)
