"""Run maintenance commands using local credentials without exposing secrets."""
from pathlib import Path
import re
import sys
import shlex
import paramiko

ROOT = Path(__file__).resolve().parents[2]

def connect():
    raw = (ROOT / '.env.local').read_text()
    pairs = dict(re.findall(r'^\s*([A-Z][A-Z0-9_]*)=(.*)$', raw, re.M))
    # Support the existing human-readable SSH section during initial setup.
    section = re.split(r'(?im)^.*web.*$', raw)[0]
    host = pairs.get('ZENSHIELD_SSH_HOST') or re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', section).group()
    user = pairs.get('ZENSHIELD_SSH_USER') or re.search(r'(?im)^username\s*:\s*(.+)$', section).group(1).strip()
    password = pairs.get('ZENSHIELD_SSH_PASSWORD') or re.search(r'(?im)^password\s*:\s*(.+)$', section).group(1).strip()
    client = paramiko.SSHClient()
    known = ROOT / '.ssh_known_hosts'
    if known.exists():
        client.load_host_keys(str(known))
    class FirstUse(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            client.get_host_keys().add(hostname, key.get_name(), key)
            client.save_host_keys(str(known))
    client.set_missing_host_key_policy(FirstUse())
    client.connect(host, username=user, password=password, timeout=15)
    client._maintenance_password = password
    return client

if __name__ == '__main__':
    client = connect()
    try:
        args = sys.argv[1:]
        sudo = args and args[0] == '--sudo'
        if sudo:
            args.pop(0)
        command = sys.stdin.read() if not args else args[0]
        if sudo:
            command = 'sudo -S -p "" sh -c ' + shlex.quote(command)
        stdin, stdout, stderr = client.exec_command(command, timeout=180)
        if sudo:
            stdin.write(client._maintenance_password + '\n')
            stdin.flush()
        sys.stdout.buffer.write(stdout.read())
        sys.stderr.buffer.write(stderr.read())
        sys.exit(stdout.channel.recv_exit_status())
    finally:
        client.close()
