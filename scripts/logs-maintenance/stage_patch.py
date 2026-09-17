"""Upload a staging tree for isolated checks, without changing running code."""
from remote import ROOT, connect
import io
import tarfile

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w:gz') as tar:
    tar.add(ROOT / 'fastapi_app/core/event_time.py', arcname='core/event_time.py')
    tar.add(ROOT / 'fastapi_app/api/appliance.py', arcname='api/appliance.py')
    tar.add(ROOT / 'fastapi_app/templates/system/appliance.html', arcname='templates/system/appliance.html')
    tar.add(ROOT / 'fastapi_app/templates/system/_ntp_panel.html', arcname='templates/system/_ntp_panel.html')
    tar.add(ROOT / 'fastapi_app/templates/logs/_detail_panel.html', arcname='templates/logs/_detail_panel.html')
    for path in (ROOT / 'appliance/control').glob('*.py'):
        tar.add(path, arcname='host-agent/'+path.name)
    for rel in ['services/correlation_engine.py', 'services/ioc_sweep.py', 'services/ioc_sightings.py', 'db/clickhouse.py', 'api/views.py', 'services/nql_schema.py', 'templates/logs/log_list.html', 'db/clickhouse_migrations/009_log_device_catalog.py', 'db/clickhouse_migrations/010_log_scope_indexes.py']:
        tar.add(ROOT / 'fastapi_app' / rel, arcname=rel)
    for path in (ROOT / 'tests').glob('*.py'):
        tar.add(path, arcname=path.name)
    tar.add(ROOT / 'reports/logs-repair-20260918/Dockerfile.logs-fix', arcname='Dockerfile')
client = connect()
try:
    sftp = client.open_sftp()
    with sftp.file('/home/net/zenshield-logfix.tar.gz', 'wb') as target:
        target.write(buf.getvalue())
    sftp.close()
    command = "sudo -S -p '' sh -c 'mkdir -p /opt/zensheild/logfix-20260917; tar xzf /home/net/zenshield-logfix.tar.gz -C /opt/zensheild/logfix-20260917; docker exec zensheild-web-1 mkdir -p /tmp/logfix; cat /home/net/zenshield-logfix.tar.gz | docker exec -i zensheild-web-1 tar xz -C /tmp/logfix'"
    stdin, stdout, stderr = client.exec_command(command)
    stdin.write(client._maintenance_password + '\n'); stdin.flush()
    stdout.read()
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Staging failed')
    print('Patch staged, running application unchanged')
finally:
    client.close()
