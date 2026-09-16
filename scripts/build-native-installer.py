import hashlib,json,re,shutil,tarfile,tempfile,sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
ROOT=Path(__file__).resolve().parents[1]
import argparse
parser=argparse.ArgumentParser(description='Build a signed native installer pinned to a verified appliance release')
parser.add_argument('--release-package', required=True)
parser.add_argument('--prior-version', default='0.2.0', help='Supported upgrade baseline used for package verification; fresh installs start directly on the candidate')
parser.add_argument('--private-key', type=Path, default=ROOT/'private/zenshield-release.key')
parser.add_argument('--output-dir', type=Path, default=ROOT/'private/native-installer')
args=parser.parse_args()
out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
release={'version':'0.3.3','min_version':'0.2.0','sha256':'ac7140c9f8f1b4293c70ef544f964a278ab6e8da62044997b8e31237f6590904','url':'https://zentryc.com/downloads/zenshield/0.3.3/ZenShield-0.3.3.zup','dependency_images':{
 'postgres':'postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685',
 'clickhouse':'clickhouse/clickhouse-server@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146',
 'redis':'valkey/valkey@sha256:d2e18f3410b6f616de1417f570fa55261af2898b9c5b2cfb6781ce2373ea43d1',
 'nginx':'nginx@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c'}}
if args.release_package:
    sys.path.insert(0,str(ROOT/'appliance'))
    from ota.package import verify,digest
    package=Path(args.release_package)
    manifest=verify(package,ROOT/'appliance/ota-release.pub','zenai',args.prior_version)
    release.update(version=manifest['version'],min_version=manifest['min_version'],sha256=digest(package),
                   url=f"https://zentryc.com/downloads/zenshield/{manifest['version']}/ZenShield-{manifest['version']}.zup")
with tempfile.TemporaryDirectory() as temp:
    stage=Path(temp)
    for source,name in [('installer/native_install.py','native_install.py'),('installer/native_setup.py','native_setup.py'),('appliance/ota/package.py','package.py'),('appliance/ota-release.pub','release.pub'),('appliance/nginx.conf','nginx.conf'),('appliance/firewall.sh','firewall.sh'),('scripts/install-updater.sh','install-updater.sh')]:
        (stage/name).write_bytes((ROOT/source).read_bytes().replace(b'\r\n',b'\n'))
    (stage/'release.json').write_text(json.dumps(release,indent=2))
    compose=(ROOT/'appliance/compose.yaml').read_text().replace('    build: ./app\n','').replace('zenshield:0.2.0','zenshield:'+release['version'])
    for old,name in [('postgres:16-alpine','postgres'),('clickhouse/clickhouse-server:25.8-alpine','clickhouse'),('valkey/valkey:8-alpine','redis'),('nginx:stable-alpine','nginx')]:compose=compose.replace(old,release['dependency_images'][name])
    (stage/'compose.yaml').write_text(compose)
    units=stage/'units';units.mkdir()
    control=(ROOT/'scripts/install-control.sh').read_text()
    agent=re.search("cat > /etc/systemd/system/zenshield-agent.service <<'EOF'\n(.*?)\nEOF",control,re.S)[1]
    (units/'zenshield-agent.service').write_text(agent+'\n')
    (units/'zensheild.service').write_text('''[Unit]
Description=ZenShield security appliance
Requires=docker.service zensheild-firewall.service zenshield-agent.service
After=docker.service zensheild-firewall.service zenshield-agent.service network-online.target
ConditionPathExists=/var/lib/zensheild/initialized
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/zensheild
ExecStart=/usr/bin/python3 /usr/local/lib/zenshield/agent.py start-services
ExecStop=/usr/bin/python3 /usr/local/lib/zenshield/agent.py stop-services
TimeoutStartSec=600
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
''')
    (units/'zensheild-firewall.service').write_text('''[Unit]
Description=ZenShield container ingress policy
Requires=docker.service
After=docker.service network-online.target
PartOf=docker.service
Before=zensheild.service
[Service]
Type=oneshot
ExecStart=/opt/zensheild/firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=docker.service
''')
    (units/'zensheild-firstboot.service').write_text('''[Unit]
Description=ZenShield first-run setup
After=network-online.target docker.service zenshield-agent.service
Requires=zenshield-agent.service
Before=getty@tty1.service
ConditionPathExists=!/var/lib/zenshield/setup-complete
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zenshield-setup
StandardInput=tty-force
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TimeoutStartSec=infinity
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
''')
    bundle=out/'bootstrap.tar.gz'
    with tarfile.open(bundle,'w:gz') as tar:
        for f in sorted(stage.rglob('*')):
            if f.is_file():
                f.write_bytes(f.read_bytes().replace(b'\r\n',b'\n'))
                tar.add(f,arcname=f.relative_to(stage).as_posix())
    data=bundle.read_bytes();sha=hashlib.sha256(data).hexdigest();name='bootstrap-'+sha[:16]+'.tar.gz'
    target=out/name
    if not target.exists():bundle.replace(target)
    else:bundle.unlink()
    key=load_pem_private_key(args.private_key.read_bytes(),password=None)
    (out/(name+'.sig')).write_bytes(key.sign(data))
    public=(ROOT/'appliance/ota-release.pub').read_text().strip()
    script='''#!/bin/bash
# ZenShield native installer. Define the complete program before executing it.
set -euo pipefail
main() {
  [[ $(id -u) == 0 ]] || { echo 'Run with sudo bash.' >&2; return 1; }
  for command in curl openssl python3; do command -v "$command" >/dev/null || { echo "Install $command first." >&2; return 1; }; done
  umask 077
  local work
  work=$(mktemp -d /tmp/zenshield-installer.XXXXXXXX)
  trap "rm -rf -- '$work'" EXIT
  cat > "$work/release.pub" <<'PUBLIC_KEY'
__PUBLIC__
PUBLIC_KEY
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 120 -A zenshield-installer/1 'https://zentryc.com/downloads/zenshield/installer/__BUNDLE__' -o "$work/bootstrap.tar.gz"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 120 -A zenshield-installer/1 'https://zentryc.com/downloads/zenshield/installer/__BUNDLE__.sig' -o "$work/bootstrap.sig"
  printf '%s  %s\n' '__SHA__' "$work/bootstrap.tar.gz" | sha256sum -c -
  openssl pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin -in "$work/bootstrap.tar.gz" -sigfile "$work/bootstrap.sig"
  python3 - "$work" <<'EXTRACT'
import sys,tarfile
from pathlib import Path,PurePosixPath
root=Path(sys.argv[1]);dest=root/'verified';dest.mkdir(mode=0o700)
with tarfile.open(root/'bootstrap.tar.gz') as tar:
    members=tar.getmembers();seen=set()
    for entry in members:
        path=PurePosixPath(entry.name)
        if not entry.isfile() or path.is_absolute() or '..' in path.parts or entry.name in seen or entry.size>5*1024**2:raise SystemExit('Unsafe bootstrap archive')
        seen.add(entry.name)
    for entry in members:
        target=dest/entry.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(tar.extractfile(entry).read())
EXTRACT
  python3 "$work/verified/native_install.py" "$@"
}
main "$@"
'''.replace('__PUBLIC__',public).replace('__BUNDLE__',name).replace('__SHA__',sha)
    (out/'install.sh').write_bytes(script.replace('\r\n','\n').encode())
    (out/'build.json').write_text(json.dumps({'bundle':name,'sha256':sha,'release':release},indent=2))
    print(json.dumps({'bundle':name,'sha256':sha}))
