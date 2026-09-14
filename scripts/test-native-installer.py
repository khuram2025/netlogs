"""Run the public installer with real first-run prompts on a designated empty VM."""
import json,secrets,sys,hashlib,subprocess,string
from pathlib import Path
import pexpect
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
assert not Path('/opt/zensheild/.env').exists()
root=Path('/root/zenshield-native-test');root.mkdir(mode=0o700,exist_ok=True)
web=secrets.token_urlsafe(24);console=secrets.token_urlsafe(24)
if '--five' in sys.argv:
    web=''.join(secrets.choice(string.ascii_lowercase) for _ in range(5))
    console=''.join(secrets.choice(string.ascii_lowercase) for _ in range(5))
enrollment=Path('/root/zenshield-native-enrollment.json')
token=json.loads(enrollment.read_text())['token'] if enrollment.exists() else ''
(root/'access.json').write_text(json.dumps({'web_password':web,'console_password':console}));(root/'access.json').chmod(0o600)
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/netplan').glob('*.yaml')}
before['ssh_key']=hashlib.sha256(Path('/home/zeninstaller/.ssh/authorized_keys').read_bytes()).hexdigest()
(root/'before.json').write_text(json.dumps(before))
command='bash /home/zeninstaller/install-candidate.sh' if '--candidate' in sys.argv else 'curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | bash'
child=pexpect.spawn('/bin/bash',['-c',command],encoding='utf-8',timeout=1200)
try:
    def answer(pattern,value):
        child.expect(pattern);print('Reached: '+pattern,flush=True);child.sendline(value)
    answer('Appliance hostname', 'zenshield-native-test')
    answer('Timezone', 'UTC')
    answer('GUI administrator password .*:',web)
    answer('Confirm password:',web)
    answer('ZenShield console password .*:',console)
    answer('Confirm password:',console)
    if '--legacy-token' in sys.argv:answer('OTA registration token .*:', token)
    child.expect(pexpect.EOF);child.close();assert child.exitstatus==0
    print('Public one-liner installation and password prompts completed',flush=True)
except Exception as e:
    text=child.before.replace(web,'[withheld]').replace(console,'[withheld]')
    if token:text=text.replace(token,'[withheld]')
    print(type(e).__name__+': '+text[-3000:]);raise SystemExit(1)
