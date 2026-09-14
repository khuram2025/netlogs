#!/usr/bin/python3
"""ZenShield appliance console. Linux maintenance requires explicit authentication."""
import cmd
import getpass
import json
import os
import shlex
import subprocess
import sys
from rpc import call

def secret(label):
    while True:
        value = getpass.getpass(label + ': ')
        if len(value) >= 5 and len(value.encode()) <= 72 and not any(c in value for c in '\n\r\x00'):
            if value == getpass.getpass('Confirm password: '): return value
        print('Use matching passwords of at least 5 characters and at most 72 UTF-8 bytes.')

def ask(label, default=''):
    return input(label + (f' [{default}]' if default else '') + ': ').strip() or default

def network_wizard():
    status = call('status')
    names = [i['ifname'] for i in status['interfaces']]
    print('Interfaces: ' + ', '.join(names))
    iface = ask('Management interface', names[0] if names else '')
    dhcp = ask('Address mode (dhcp/static)', 'dhcp').lower() == 'dhcp'
    data = {'interface': iface, 'dhcp': dhcp}
    if not dhcp:
        data.update(address=ask('IPv4 address/prefix'), gateway=ask('Default gateway'))
    data['dns'] = ask('DNS servers, comma separated (empty keeps DHCP DNS)').split(',')
    data['dns'] = [x.strip() for x in data['dns'] if x.strip()]
    return data

def apply_network(data):
    result = call('network.apply', **data)
    print(result['message'])
    print('After verifying connectivity, enter: confirm ' + result['token'])
    return result

def wizard():
    print('\nZenShield configuration wizard\n')
    status = call('status')
    hostname = ask('Appliance hostname', status['hostname'])
    timezone = ask('Timezone', status['timezone'])
    ntp = ask('Additional NTP server (empty keeps current)')
    settings = {'hostname': hostname, 'timezone': timezone}
    if ntp: settings['ntp'] = ntp
    if ask('Configure management network? (yes/no)', 'no') == 'yes':
        result = apply_network(network_wizard())
        if ask('Verify the IP above is reachable, then type KEEP', 'REVERT') == 'KEEP':
            call('network.confirm', token=result['token'])
        else:
            call('network.rollback')
            print('Previous network restored.')
    print(call('settings.update', **settings)['message'])
    if ask('Change GUI admin password? (yes/no)', 'yes') == 'yes':
        print(call('password.gui', password=secret('New GUI admin password'))['message'])
    print('Configuration complete. Use show status to inspect the appliance.')

class Console(cmd.Cmd):
    intro = '\nZenShield | Security appliance\nType help for commands. Type setup for guided configuration.\n'
    prompt = 'ZenShield> '
    def __init__(self):
        super().__init__()
        self.intro=self.intro.replace('ZenShield |','ZenShield '+call('status')['version']+' |')
        self.candidate = {}
        self.configuring = False
    def emptyline(self): pass
    def default(self, line): print('Unknown command. Type help.')
    def onecmd(self, line):
        try: return super().onecmd(line)
        except (ValueError, OSError, KeyError) as exc: print('Error:', exc)
        except KeyboardInterrupt: print('\nCancelled.')
    def do_help(self, arg):
        print('''show version | status | interfaces | ip | routes | dns | storage | services | running-config
ping <IP-or-hostname>
setup                         Guided appliance configuration
configure terminal            Enter configuration mode
  hostname <name>              Stage hostname
  timezone <Region/City>       Stage timezone
  ntp <server>                Stage additional NTP server
  network                     Stage network using prompts
  commit                      Apply staged settings; network rolls back in 120s
  end                         Discard staged settings and leave configuration mode
confirm <token>               Keep a pending network change
rollback                      Restore previous network configuration
password gui                  Change GUI administrator password (masked)
password console              Change your console / expert password
service restart <name>        Restart an appliance service
storage rescan                Discover attached and expanded disks
storage grow-system           Expand the existing system filesystem
storage grow <volume> <GiB>    Set a larger ClickHouse/application volume size
storage migrate               Retry a staged data migration
show updates                  Release status and installation history
update check                  Check for an eligible release
update register               Register with a masked token
update install                Confirm and install the offered release
expert                        Authenticated Linux maintenance shell
exit                          Sign out''')
    def do_show(self, arg):
        if arg=='updates':print(json.dumps(call('updates.status'),indent=2));return
        arg = {'ip interface brief':'interfaces','interface brief':'interfaces','ip route':'routes','clock':'clock'}.get(arg,arg)
        if arg == 'version': print('ZenShield '+call('status')['version']+' | Virtual security appliance'); return
        if arg == 'storage': data = call('storage')
        else:
            status = call('status')
            if arg in {'interfaces','ip'}:
                print(f"{'Interface':16} {'Address/prefix':25} {'State':12} MAC address")
                for interface in status['interfaces']:
                    addresses=', '.join(a['local']+'/'+str(a['prefixlen']) for a in interface['addr_info'] if a['family']=='inet') or 'unassigned'
                    print(f"{interface['ifname']:16} {addresses:25} {interface['operstate']:12} {interface.get('address','')}")
                return
            if arg == 'routes':
                print(f"{'Destination':22} {'Gateway':20} Interface")
                for route in status['routes']:
                    if route.get('dev') in [i['ifname'] for i in status['interfaces']]:
                        print(f"{route['dst']:22} {route.get('gateway','connected'):20} {route.get('dev','')}")
                return
            if arg == 'services':
                raw=status['services'].strip()
                services=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line]
                for service in services: print(f"{service['Service']:16} {service.get('Health') or service.get('State')}")
                return
            if arg == 'clock': print(status['timezone']); return
            key = {'interfaces':'interfaces', 'ip':'interfaces', 'routes':'routes', 'dns':'dns', 'services':'services'}.get(arg)
            if key: data = status[key]
            elif arg in {'status','running-config'}: data = status
            else: raise ValueError('Use show version/status/interfaces/ip/routes/dns/storage/services/running-config')
        print(data if isinstance(data, str) else json.dumps(data, indent=2))
    def do_ping(self, arg): print(call('diagnostic.ping', target=arg.strip())['output'])
    def do_storage(self, arg):
        parts = arg.split()
        if parts in (['rescan'], ['grow-system'], ['migrate']):
            body = {'action': parts[0]}
        elif len(parts) == 3 and parts[0] == 'grow' and parts[1] in {'clickhouse', 'application'}:
            body = {'action': 'grow', 'volume': parts[1], 'size_gib': int(parts[2])}
        else:
            raise ValueError('Use storage rescan | grow-system | migrate | grow <clickhouse|application> <GiB>')
        plan = call('storage.plan', **body)
        print(plan['summary'])
        print('Confirmation: ' + plan['confirmation'])
        confirmation = input('Type the confirmation phrase, or press Enter to cancel: ')
        if not confirmation:
            print('Cancelled.'); return
        job = call('storage.commit', token=plan['token'], confirmation=confirmation)
        print('Storage operation queued: ' + job['id'] + '. Use show storage to inspect progress.')
    def do_setup(self, arg): wizard()
    def do_update(self,arg):
        if arg=='check':print(call('updates.check')['message'])
        elif arg=='register':print(call('updates.register',token=getpass.getpass('ZenShield registration token: '))['message'])
        elif arg=='install':
            status=call('updates.status');offer=status['offer']
            if not offer:raise ValueError('No update offered. Use update check first.')
            print('Installing '+offer['version']+' pauses GUI and collection while data is backed up.')
            confirmation=input('Type INSTALL '+offer['version']+': ')
            print(call('updates.apply',release_id=offer['release_id'],confirmation=confirmation)['message'])
        else:print('show updates | update check | update register | update install')
    def do_configure(self, arg):
        if arg != 'terminal': raise ValueError('Use configure terminal')
        self.configuring = True
        self.prompt = 'ZenShield(config)# '
    def stage(self, key, value):
        if not self.configuring: raise ValueError('Enter configure terminal first')
        self.candidate[key] = value
        print('Staged. Use commit to apply.')
    def do_hostname(self, arg): self.stage('hostname', arg.strip())
    def do_timezone(self, arg): self.stage('timezone', arg.strip())
    def do_ntp(self, arg): self.stage('ntp', arg.strip())
    def do_network(self, arg):
        if not self.configuring: raise ValueError('Enter configure terminal first')
        self.stage('network', network_wizard())
    def do_commit(self, arg):
        settings = {k:v for k,v in self.candidate.items() if k != 'network'}
        if settings: print(call('settings.update', **settings)['message'])
        if 'network' in self.candidate: apply_network(self.candidate['network'])
        self.candidate = {}
    def do_confirm(self, arg): print(call('network.confirm', token=arg.strip())['message'])
    def do_rollback(self, arg): print(call('network.rollback')['message'])
    def do_end(self, arg):
        self.candidate = {}; self.configuring = False; self.prompt = 'ZenShield> '
    def do_password(self, arg):
        if arg == 'gui': print(call('password.gui', password=secret('New GUI admin password'))['message'])
        elif arg == 'console':
            value=secret('New ZenShield console password (minimum 5 characters)')
            # Authenticate before changing the fixed appliance account; never pass
            # the new password in argv or relax the system-wide PAM policy.
            subprocess.run(['/usr/bin/sudo','-v'],check=True)
            subprocess.run(['/usr/bin/sudo','-n','/usr/sbin/chpasswd'],input='zenadmin:'+value+'\n',text=True,check=True)
            print('ZenShield console password changed.')
        else: raise ValueError('Use password gui or password console')
    def do_service(self, arg):
        parts = shlex.split(arg)
        if len(parts) != 2 or parts[0] != 'restart': raise ValueError('Use service restart <name>')
        print(call('service.restart', service=parts[1])['message'])
    def do_expert(self, arg):
        if not sys.stdin.isatty(): raise ValueError('Expert maintenance requires an interactive console')
        print('ZenShield expert maintenance. Authenticate with your console password; exit returns here.')
        subprocess.run(['/usr/bin/sudo', '-k'])
        subprocess.run(['/usr/bin/sudo', '/bin/bash', '--noprofile', '--norc'])
    def do_exit(self, arg): return True
    def do_EOF(self, arg): print(); return True

if __name__ == '__main__':
    console = Console()
    if len(sys.argv) > 1:
        if len(sys.argv) == 3 and sys.argv[1] == '-c':
            # SSH command execution supports read-only appliance commands only.
            command = sys.argv[2]
            if command.split(' ', 1)[0] not in {'show', 'ping', 'help'}:
                raise SystemExit('SSH command execution accepts show, ping and help. Use an interactive session to configure ZenShield.')
            console.onecmd(command)
        else: raise SystemExit('Use an interactive ZenShield console')
    else:
        try: console.cmdloop()
        except (EOFError, KeyboardInterrupt): print('\nSigned out.')
