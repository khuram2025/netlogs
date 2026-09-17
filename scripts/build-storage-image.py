"""Build the complete storage/DNS release over the last published appliance image."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
base, tag = sys.argv[1:3]
if subprocess.run(['docker', 'image', 'inspect', tag], capture_output=True).returncode == 0:
    raise SystemExit('Refusing to replace an existing image tag')
with tempfile.TemporaryDirectory(prefix='zenshield-storage-build-') as temporary:
    stage = Path(temporary)
    (stage / 'scripts').mkdir()
    (stage / 'appliance/control').mkdir(parents=True)
    for name in ('patch-dns.py', 'patch-storage.py'):
        shutil.copyfile(root / 'scripts' / name, stage / 'scripts' / name)
    for name in ('api.py', 'system.html', '_ntp_panel.html', 'storage_monitor.py'):
        shutil.copyfile(root / 'appliance/control' / name, stage / 'appliance/control' / name)
    shutil.copytree(root / 'appliance/dns', stage / 'appliance/dns')
    shutil.copytree(root / 'appliance/dns-agent-release', stage / 'dns-agent')
    (stage / 'brand.py').write_text("from pathlib import Path\nimport re\np=Path('/app/fastapi_app/templates/base.html');p.write_text(re.sub(r'ZenShield 0\\.\\d+\\.\\d+', 'ZenShield " + tag.split(':')[1] + "', p.read_text()))\n")
    (stage / 'Dockerfile').write_text(f'''FROM {base}
USER root
COPY scripts /tmp/zenshield/scripts
COPY appliance /tmp/zenshield/appliance
RUN python /tmp/zenshield/scripts/patch-dns.py /app && python /tmp/zenshield/scripts/patch-storage.py /app && rm -r /tmp/zenshield
COPY dns-agent /app/dns-agent
COPY brand.py /tmp/brand.py
RUN python /tmp/brand.py && rm /tmp/brand.py
USER 1000
LABEL org.opencontainers.image.title="ZenShield" org.opencontainers.image.version="{tag.split(':')[1]}"
''')
    subprocess.run(['docker', 'build', '-t', tag, str(stage)], check=True)
print(json.dumps({'image': tag, 'image_id': subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag], text=True).strip()}))
