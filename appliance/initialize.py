#!/usr/bin/python3
"""Initialize instance-specific secrets; interactive after a sealed clone boots."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
sys.path.insert(0, '/usr/local/lib/zenshield')

BASE = Path('/opt/zensheild')
MARKER = Path('/var/lib/zensheild/initialized')

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def password(prompt):
    while True:
        value = getpass.getpass(prompt)
        if len(value) >= 5 and len(value.encode()) <= 72 and not any(c in value for c in "\r\n\x00'\\") and value == getpass.getpass('Confirm password: '):
            return value
        print('Use at least 5 characters and at most 72 UTF-8 bytes, matching entries, and no apostrophes or backslashes.')

def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    complete = Path('/var/lib/zenshield/setup-complete')
    if complete.exists(): return
    if MARKER.exists():
        run('systemctl', 'start', 'zensheild.service')
        complete.parent.mkdir(parents=True, exist_ok=True)
        complete.write_text('ZenShield setup complete\n')
        print('ZenShield configured. Sign in over HTTPS as admin.')
        return
    os.umask(0o077)
    build = '--build' in sys.argv
    if build:
        admin_password = secrets.token_urlsafe(24)
        console_password = secrets.token_urlsafe(24)
        hostname = 'zenshield'
        management = '192.168.18.0/24'
    else:
        from cli import network_wizard
        from rpc import call
        print('\033[2J\033[HZenShield appliance — first-run configuration\n')
        print('Step 1 of 4: management network. Changes revert after 120 seconds unless confirmed.')
        network = network_wizard()
        result = call('network.apply', **network)
        time.sleep(4)
        for interface in call('status')['interfaces']:
            addresses = ', '.join(a['local'] + '/' + str(a['prefixlen']) for a in interface['addr_info'] if a['family'] == 'inet')
            print(interface['ifname'] + ': ' + (addresses or 'No IPv4 address assigned'))
        if input('Verify this address is reachable, then type KEEP (anything else reverts): ').strip() == 'KEEP':
            call('network.confirm', token=result['token'])
        else:
            call('network.rollback')
            print('Previous network restored. Restart the wizard to configure connectivity.')
            raise SystemExit(1)
        print('Step 2 of 4: appliance identity and time.')
        while True:
            hostname = input('Hostname [zenshield]: ').strip() or 'zenshield'
            if re.fullmatch(r'[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]', hostname):
                break
        zone = input('Timezone [UTC]: ').strip() or 'UTC'
        ntp = input('Additional NTP server (optional): ').strip()
        settings = {'hostname': hostname, 'timezone': zone}
        if ntp: settings['ntp'] = ntp
        call('settings.update', **settings)
        print('Step 3 of 4: unique administrator credentials.')
        admin_password = password('GUI administrator password: ')
        console_password = password('Console zenadmin password: ')
        print('Step 4 of 4: management access.')
        while True:
            try:
                management = str(ipaddress.ip_network(input('SSH management IPv4 CIDR: ').strip()))
                if ipaddress.ip_network(management).version == 4:
                    break
            except ValueError:
                pass
            print('Enter an IPv4 network, e.g. 192.168.1.0/24.')
    run('hostnamectl', 'set-hostname', hostname)
    hosts = Path('/etc/hosts')
    host_lines = [line for line in hosts.read_text().splitlines() if not line.startswith('127.0.1.1')]
    hosts.write_text('\n'.join(host_lines) + f'\n127.0.1.1 {hostname}\n')
    run('chpasswd', input=f'zenadmin:{console_password}\n', text=True)
    env = {
        'SECRET_KEY': secrets.token_hex(48),
        'POSTGRES_PASSWORD': secrets.token_hex(32),
        'CLICKHOUSE_PASSWORD': secrets.token_hex(32),
        'REDIS_PASSWORD': secrets.token_hex(32),
        'ZENSHEILD_ADMIN_PASSWORD': admin_password,
    }
    # Compose interpolation is disabled within single-quoted env values.
    # Reject newlines and quotes rather than transforming user passwords.
    if any(c in admin_password for c in "\r\n'\\"):
        raise SystemExit('Web password cannot contain quotes, backslashes or newlines.')
    (BASE / '.env').write_text(''.join(f"{k}='{v}'\n" for k, v in env.items()))
    (BASE / '.env').chmod(0o600)
    certs = BASE / 'certs'
    certs.mkdir(exist_ok=True)
    ips = subprocess.check_output(['hostname', '-I'], text=True).split()
    sans = [f'DNS:{hostname}', 'DNS:localhost', 'IP:127.0.0.1']
    sans += [f'IP:{ip}' for ip in ips if ipaddress.ip_address(ip).version == 4]
    run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365',
        '-keyout', str(certs / 'server.key'), '-out', str(certs / 'server.crt'),
        '-subj', f'/CN={hostname}', '-addext', 'subjectAltName=' + ','.join(sans),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (certs / 'server.key').chmod(0o600)
    (certs / 'server.crt').chmod(0o644)
    run('ufw', 'allow', 'from', management, 'to', 'any', 'port', '22', 'proto', 'tcp')
    run('ufw', '--force', 'enable')
    if not build:
        Path('/etc/sudoers.d/90-cloud-init-users').unlink(missing_ok=True)
        Path('/etc/sudoers.d/zensheild-admin').write_text('zenadmin ALL=(ALL:ALL) ALL\n')
        Path('/etc/sudoers.d/zensheild-admin').chmod(0o440)
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    # Generate deployment secrets only once, even when services need repair.
    MARKER.write_text('ZenShield 0.2.0 initialized\n')
    if build:
        Path('/root/zensheild-build-access.json').write_text(json.dumps({
            'web_user': 'admin', 'web_password': admin_password,
            'console_user': 'zenadmin', 'console_password': console_password,
        }, indent=2))
    else:
        run('systemctl', 'start', 'zensheild.service')
        complete.parent.mkdir(parents=True, exist_ok=True)
        complete.write_text('ZenShield setup complete\n')
        from ota.transport import sync_licence
        try:sync_licence()
        except Exception:print('Registration is pending and will retry automatically. See System > Licences.')
        print('ZenShield configured. Sign in over HTTPS as admin. Use setup to change settings later.')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nSetup interrupted. The console wizard will restart.')
        raise SystemExit(1)
    except Exception as exc:
        print('\nZenShield setup could not finish: ' + str(exc))
        print('Your saved instance secrets are retained. Retry setup to continue.')
        raise SystemExit(1)
