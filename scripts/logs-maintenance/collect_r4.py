"""Collect metric-only verification and a portable source patch."""
from remote import ROOT, connect
import difflib
import io
import json
import shlex
import sys
import tarfile

out = ROOT / 'reports/logs-repair-20260918'
client = connect()
def command(cmd):
    stdin, stdout, stderr = client.exec_command('sudo -S -p "" sh -c ' + shlex.quote(cmd), timeout=180)
    stdin.write(client._maintenance_password + '\n'); stdin.flush()
    data = stdout.read()
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Collection command failed')
    return data

try:
    if len(sys.argv) > 1:
        name = sys.argv[1]
        raw = command('docker exec zensheild-web-1 cat /tmp/' + shlex.quote(name)).decode()
        rows = []
        for line in raw.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if 'case' in item or 'suggest_minutes' in item or 'cases' in item:
                rows.append(item)
        (out / (name.replace('.jsonl', '.json'))).write_text(json.dumps(rows, indent=2), encoding='utf-8')
        print('Collected', len(rows), 'metric records')
    names = ['templates/logs/_detail_panel.html', 'api/appliance.py', 'templates/system/appliance.html', 'core/event_time.py', 'services/nql_schema.py', 'services/correlation_engine.py', 'services/ioc_sweep.py', 'services/ioc_sightings.py']
    data = command('docker run --rm --entrypoint tar zenshield:0.4.3 -czf - -C /app/fastapi_app ' + ' '.join(names))
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for name in names:
            target = ROOT / 'baseline' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(name).read())
finally:
    client.close()

patch = []
names += ['templates/system/_ntp_panel.html', 'db/clickhouse.py', 'api/views.py', 'templates/logs/log_list.html', 'db/clickhouse_migrations/009_log_device_catalog.py', 'db/clickhouse_migrations/010_log_scope_indexes.py']
for name in names:
    baseline = ROOT / 'baseline' / name
    before = baseline.read_text(encoding='utf-8').splitlines(True) if baseline.exists() else []
    after = (ROOT / 'fastapi_app' / name).read_text(encoding='utf-8').splitlines(True)
    patch.extend(difflib.unified_diff(before, after, fromfile='a/fastapi_app/' + name if baseline.exists() else '/dev/null', tofile='b/fastapi_app/' + name))
(out / 'logs-fix.patch').write_text(''.join(patch), encoding='utf-8')
print('Portable patch updated for', len(names), 'source files')
patch = []
for name in ['agent.py', 'ntp.py']:
    baseline = ROOT / 'baseline/host-agent' / name
    before = baseline.read_text(encoding='utf-8').splitlines(True) if baseline.exists() else []
    after = (ROOT / 'appliance/control' / name).read_text(encoding='utf-8').splitlines(True)
    patch.extend(difflib.unified_diff(before, after, fromfile='a/host-agent/'+name if baseline.exists() else '/dev/null', tofile='b/host-agent/'+name))
(out / 'host-ntp.patch').write_text(''.join(patch), encoding='utf-8')
