"""Enable scoped nginx compression, with configuration validation and rollback."""
from remote import ROOT, connect
import shlex

client = connect()
try:
    sftp = client.open_sftp()
    path = '/opt/zensheild/nginx.conf'
    stdin, stdout, stderr = client.exec_command('sudo -S -p "" cat '+shlex.quote(path))
    stdin.write(client._maintenance_password+'\n'); stdin.flush()
    before = stdout.read().decode()
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Cannot read nginx configuration')
    marker = '    location / { proxy_pass http://web:8000; }'
    block = '''    # Compress the large log viewer response; keep authentication routes unchanged.
    location = /logs/ {
        gzip on;
        gzip_vary on;
        gzip_min_length 1024;
        gzip_comp_level 5;
        proxy_pass http://web:8000;
    }
'''
    if 'location = /logs/' in before:
        raise RuntimeError('Logs location already configured; inspect before updating')
    assert before.count(marker) == 1
    after = before.replace(marker, block + marker)
    (ROOT / 'reports/logs-repair-20260918/nginx.logs-fix.conf').write_text(after)
    (ROOT / 'baseline/nginx.before-r4.conf').write_text(before)
    with sftp.file('/home/net/nginx.logs-fix.conf', 'w') as f:
        f.write(after)
    sftp.close()
    command = '''set -e
cp /opt/zensheild/nginx.conf /opt/zensheild/logfix-20260917/nginx.before-r4.conf
cat /home/net/nginx.logs-fix.conf > /opt/zensheild/nginx.conf
if ! docker exec zensheild-nginx-1 nginx -t; then
    cat /opt/zensheild/logfix-20260917/nginx.before-r4.conf > /opt/zensheild/nginx.conf
    exit 1
fi
docker exec zensheild-nginx-1 nginx -s reload
'''
    stdin, stdout, stderr = client.exec_command('sudo -S -p "" sh -c '+shlex.quote(command))
    stdin.write(client._maintenance_password+'\n'); stdin.flush()
    output = stdout.read()
    errors = stderr.read()
    status = stdout.channel.recv_exit_status()
    print(output.decode(), end='')
    print(errors.decode(), end='')
    if status:
        raise RuntimeError('Nginx validation/reload failed')
    print('Log page compression configured and nginx reloaded')
finally:
    client.close()
