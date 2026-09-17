from remote import ROOT, connect
import difflib
import json
import statistics

out = ROOT / 'reports/logs-repair-20260918'
out.mkdir(exist_ok=True)
client = connect()
try:
    sftp = client.open_sftp()
    raw = sftp.file('/tmp/zenshield-logfix-results-v2.jsonl').read().decode()
    rows = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if 'case' in value:
            rows.append(value)
    (out / 'live-matrix.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
    print(json.dumps({'cases': len(rows), 'failures': sum(bool(r['error']) for r in rows),
                      'median_seconds': statistics.median(r['seconds'] for r in rows)}))
finally:
    client.close()

patch = []
for name in ['db/clickhouse.py', 'api/views.py', 'templates/logs/log_list.html']:
    before = (ROOT / 'baseline' / name).read_text(encoding='utf-8').splitlines(True)
    after = (ROOT / 'fastapi_app' / name).read_text(encoding='utf-8').splitlines(True)
    patch.extend(difflib.unified_diff(before, after, fromfile='a/fastapi_app/' + name, tofile='b/fastapi_app/' + name))
name = 'db/clickhouse_migrations/009_log_device_catalog.py'
after = (ROOT / 'fastapi_app' / name).read_text(encoding='utf-8').splitlines(True)
patch.extend(difflib.unified_diff([], after, fromfile='/dev/null', tofile='b/fastapi_app/' + name))
(out / 'logs-fix.patch').write_text(''.join(patch), encoding='utf-8')
