#!/usr/bin/python3
"""First setup for an existing Ubuntu host; preserve its network and SSH owner."""
import getpass,ipaddress,json,os,secrets,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/zenshield')
sys.path.insert(0,'/opt/zensheild')
from ota.common import BASE,CONFIG,write,config,compose,current_version
from rpc import call

def password(prompt):
    """Give a specific correction without exposing the entered password."""
    print('Password input is hidden; no characters or asterisks will appear.')
    print('Use at least 5 characters and at most 72 UTF-8 bytes. No uppercase, number or symbol is required. Spaces are allowed. Do not use apostrophes or backslashes. Press Ctrl+C to pause setup.')
    while True:
        value=getpass.getpass(prompt)
        size=len(value.encode('utf-8'))
        if len(value)<5:
            print(f'Password too short: received {len(value)} characters; at least 5 are required.')
            continue
        if size>72:
            print(f'Password too long: received {size} UTF-8 bytes; at most 72 are allowed. Non-English characters may use several bytes each.')
            continue
        if any(c in value for c in "\r\n\x00'\\"):
            print('Password contains an unsupported character: apostrophe, backslash, line break or NUL. Remove it and try again.')
            continue
        if value!=getpass.getpass('Confirm password: '):
            print('Passwords do not match. Enter the same password twice; check Caps Lock and keyboard layout.')
            continue
        return value

def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def main():
    if os.geteuid()!=0:raise SystemExit('Use sudo zenshield-setup')
    complete=Path('/var/lib/zenshield/setup-complete')
    if complete.exists():
        print('ZenShield is already configured. Use sudo zenshield for management.');return
    marker=Path('/var/lib/zensheild/initialized')
    if not marker.exists():
        print('\nZenShield '+current_version()+' — first-time setup')
        print('Your current network configuration and existing Ubuntu administrator access are preserved.')
        print('Change IP settings later with System > Network or configure terminal > network.')
        hostname=input('Appliance hostname [zenshield]: ').strip() or 'zenshield'
        zone=input('Timezone [UTC]: ').strip() or 'UTC'
        call('settings.update',hostname=hostname,timezone=zone)
        web=password('GUI administrator password (minimum 5 characters): ')
        console=password('ZenShield console password (minimum 5 characters): ')
        run('chpasswd',input='zenadmin:'+console+'\n',text=True)
        env={'SECRET_KEY':secrets.token_hex(48),'POSTGRES_PASSWORD':secrets.token_hex(32),'CLICKHOUSE_PASSWORD':secrets.token_hex(32),'REDIS_PASSWORD':secrets.token_hex(32),'ZENSHEILD_ADMIN_PASSWORD':web}
        write(BASE/'.env',''.join(k+"='"+v+"'\n" for k,v in env.items()))
        certs=BASE/'certs';certs.mkdir(exist_ok=True)
        ips=subprocess.check_output(['hostname','-I'],text=True).split()
        sans=['DNS:'+hostname,'DNS:localhost','IP:127.0.0.1']+['IP:'+a for a in ips if ipaddress.ip_address(a).version==4]
        run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365','-keyout',str(certs/'server.key'),'-out',str(certs/'server.crt'),'-subj','/CN='+hostname,'-addext','subjectAltName='+','.join(sans),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (certs/'server.key').chmod(0o600);(certs/'server.crt').chmod(0o644)
        marker.parent.mkdir(parents=True,exist_ok=True);write(marker,'ZenShield '+current_version()+' initialized\n')
    print('Starting ZenShield services and validating health. This can take several minutes.')
    run('systemctl','start','zensheild.service')
    services=[json.loads(row) for row in compose('ps','--format','json').splitlines()]
    if len(services)!=6 or any(s.get('Health')!='healthy' for s in services):raise RuntimeError('Services are not healthy; instance secrets are retained. Rerun sudo zenshield-setup.')
    write(complete,'ZenShield setup complete\n')
    print('ZenShield configured. All six services are healthy.')
    print('GUI username: admin. Console username: zenadmin.')
    ips=subprocess.check_output(['hostname','-I'],text=True).split()
    print('HTTPS management addresses: '+', '.join('https://'+a+'/system/' for a in ips if ipaddress.ip_address(a).version==4))
    print('The instance has a unique self-signed certificate. Verify its fingerprint before trusting it; use an organization-issued certificate for deployment.')
    fingerprint=subprocess.check_output(['openssl','x509','-in',str(BASE/'certs/server.crt'),'-noout','-fingerprint','-sha256'],text=True).strip();print(fingerprint)
    print('Registering this appliance with Zentryc for its unrestricted 30-day trial…')
    from ota.transport import sync_licence
    try:
        licence=sync_licence()
        print('Registration complete. View your licence and expiry under System > Licences.')
    except Exception:
        print('Registration is pending. It will retry automatically; check System > Licences for status.')
    print('Automatic updates are off. Use sudo zenshield, show services, show storage, or show updates.')
if __name__=='__main__':
    try:main()
    except (KeyboardInterrupt,EOFError):raise SystemExit('Setup paused. Resume with sudo zenshield-setup.')
