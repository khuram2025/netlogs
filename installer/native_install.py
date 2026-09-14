#!/usr/bin/python3
"""Install the verified ZenShield release on a dedicated Ubuntu host."""
import argparse,errno,fcntl,hashlib,http.client,json,os,platform,shutil,socket,ssl,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE=Path('/opt/zensheild');STATE=Path('/var/lib/zenshield-installer')
RELEASE=json.loads((HERE/'release.json').read_text())
def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def output(*args):return subprocess.check_output(args,text=True).strip()
def write(path,text,mode=0o644):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(mode)
def console_access():
    import grp
    library=Path('/usr/local/lib/zenshield')
    BASE.chmod(0o755);library.chmod(0o755)
    for name in ('agent.py','rpc.py','cli.py'):(library/name).chmod(0o644)
    try:group=grp.getgrgid(1000).gr_name
    except KeyError:run('groupadd','--gid','1000','zenshield-api');group='zenshield-api'
    # The signed agent socket and application image use group 1000.
    run('usermod','--append','--groups',group,'zenadmin')
def warn_resources():
    """Sizing is advisory; never reject a host based on CPU, RAM or disk capacity."""
    warnings=[]
    try:
        cpus=os.cpu_count()
        if cpus is None:warnings.append('CPU count is unavailable; 4 logical CPUs are recommended.')
        elif cpus<4:warnings.append(f'{cpus} logical CPU(s) detected; 4 are recommended.')
    except OSError:
        warnings.append('CPU count could not be read; 4 logical CPUs are recommended.')
    try:
        memory=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))*1024
        if memory<15*1024**3:warnings.append(f'{memory/1024**3:.1f} GiB RAM detected; approximately 16 GiB is recommended.')
    except (OSError,ValueError,IndexError,StopIteration):
        warnings.append('Memory capacity could not be read; approximately 16 GiB RAM is recommended.')
    try:
        disk=shutil.disk_usage('/opt')
        if disk.total<100*1024**3 or disk.free<30*1024**3:
            warnings.append(f'The /opt filesystem has {disk.total/1024**3:.1f} GiB total and {disk.free/1024**3:.1f} GiB free; 100 GiB total and 30 GiB free are recommended.')
    except OSError:
        warnings.append('Storage capacity could not be read; 100 GiB total and 30 GiB free on the /opt filesystem are recommended.')
    for warning in warnings:print('WARNING: '+warning,flush=True)
    if warnings:print('Continuing automatically. CPU, RAM and disk sizing are advisory. Low resources may slow installation or prevent services from starting; actual out-of-memory or disk-full errors still require more resources.',flush=True)

def preflight():
    os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os_release.get('ID','').strip('"')!='ubuntu' or os_release.get('VERSION_ID','').strip('"')!='24.04':raise RuntimeError('This signed release supports Ubuntu Server 24.04 LTS only. No OS upgrade will be attempted.')
    if platform.machine()!='x86_64':raise RuntimeError('amd64/x86_64 is required; ARM is not supported by this release.')
    if Path('/proc/1/comm').read_text().strip()!='systemd' or Path('/.dockerenv').exists():raise RuntimeError('Install on a native systemd server or full VM, not inside a container.')
    warn_resources()
    resume=(STATE/'state.json').exists()
    if BASE.exists() and not resume:raise RuntimeError('Existing appliance directory found. Use the appliance updater, not the native installer.')
    if not resume:
        import pwd
        try:pwd.getpwnam('zenadmin')
        except KeyError:pass
        else:raise RuntimeError('The zenadmin account already exists; use a dedicated clean host.')
        if shutil.which('docker'):
            for command in (['ps','-aq'],['volume','ls','-q']):
                r=subprocess.run(['docker',*command],capture_output=True,text=True)
                if r.returncode or r.stdout.strip():raise RuntimeError('Existing or unavailable Docker installation detected. Use a clean dedicated server.')
        for kind,port in ((socket.SOCK_STREAM,80),(socket.SOCK_STREAM,443),(socket.SOCK_DGRAM,514)):
            with socket.socket(socket.AF_INET,kind) as probe:
                try:probe.bind(('0.0.0.0',port))
                except OSError:raise RuntimeError('Required port '+str(port)+' is already in use.')
    print('Preflight passed: Ubuntu 24.04 amd64, systemd and dedicated-host checks. Resource sizing is advisory.')
    return resume
def transient_download_error(error):
    if isinstance(error,urllib.error.HTTPError):return error.code in (408,429,500,502,503,504)
    reason=error.reason if isinstance(error,urllib.error.URLError) else error
    if isinstance(reason,ssl.SSLError):return False
    if isinstance(reason,socket.gaierror):return reason.errno==socket.EAI_AGAIN
    return isinstance(reason,(TimeoutError,ConnectionError,http.client.IncompleteRead)) or (
        isinstance(reason,OSError) and reason.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ENETDOWN,errno.ETIMEDOUT))

def download(url,path,expected):
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==expected:return
    request=urllib.request.Request(url,headers={'User-Agent':'zenshield-installer/1'})
    temp=path.with_suffix('.part');delays=(5,10,20,30,30)
    for attempt in range(len(delays)+1):
        h=hashlib.sha256();size=0
        try:
            with urllib.request.urlopen(request,timeout=60) as response,temp.open('wb') as target:
                if not response.url.startswith('https://zentryc.com/'):raise RuntimeError('Unapproved release redirect')
                while block:=response.read(1024*1024):
                    size+=len(block)
                    if size>2*1024**3:raise RuntimeError('Package download exceeds the 2 GiB release size limit')
                    h.update(block);target.write(block)
            if h.hexdigest()!=expected:raise RuntimeError('Release SHA256 mismatch')
            temp.replace(path)
            return
        except (OSError,http.client.HTTPException) as error:
            if not transient_download_error(error):raise
            if attempt==len(delays):
                raise RuntimeError('Release download failed after 6 attempts because DNS or the network is still unavailable. Run "getent hosts zentryc.com" and "resolvectl status" to check DNS, and verify outbound HTTPS access. Then rerun the same installer; completed downloads and existing data are retained') from error
            reason=error.reason if isinstance(error,urllib.error.URLError) else error
            label='Temporary DNS resolution failure' if isinstance(reason,socket.gaierror) else 'Temporary release download failure'
            print(f'WARNING: {label} (attempt {attempt+1}/6). Retrying in {delays[attempt]} seconds; network services may still be recovering after package installation.',flush=True)
        finally:
            temp.unlink(missing_ok=True)
        time.sleep(delays[attempt])
def install():
    preflight()
    STATE.mkdir(mode=0o700,exist_ok=True)
    if (STATE/'complete').exists() and (BASE/'.version').read_text().strip()!=RELEASE['version']:
        if Path('/var/lib/zensheild/initialized').exists():
            raise RuntimeError('An initialized older release exists. Use System > Updates to upgrade it; the native installer will not replace initialized application data.')
        print('Refreshing the release for unfinished first-time setup; existing host settings are retained.')
    elif (STATE/'complete').exists():
        if not Path('/var/lib/zenshield/setup-complete').exists():
            # A signed bootstrap fix must also reach hosts paused in first setup.
            replacement=BASE/'native_setup.py.next'
            shutil.copyfile(HERE/'native_setup.py',replacement)
            replacement.chmod(0o644)
            replacement.replace(BASE/'native_setup.py')
        console_access()
        print('ZenShield is already installed. Use sudo zenshield-setup to finish setup, or System > Updates for upgrades.');return
    write(STATE/'state.json',json.dumps({'version':RELEASE['version'],'installer_format':1}),0o600)
    print('Installing Ubuntu repository dependencies…')
    env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'}
    run('apt-get','update',env=env)
    run('apt-get','install','-y','docker.io','docker-compose-v2','python3-cryptography','python3-yaml','lvm2','rsync','cloud-guest-utils','xfsprogs','ufw','chrony','auditd','fail2ban','unattended-upgrades','openssl','ca-certificates','curl','openssh-server','netplan.io',env=env)
    archive=STATE/('ZenShield-'+RELEASE['version']+'.zup')
    print('Downloading and verifying the signed OTA release…')
    download(RELEASE['url'],archive,RELEASE['sha256'])
    from package import verify
    with tempfile.TemporaryDirectory(prefix='verified-',dir=STATE) as folder:
        verified=Path(folder)/'release'
        manifest=verify(archive,HERE/'release.pub','zenai',RELEASE['min_version'],offer={'package_sha256':RELEASE['sha256'],'version':RELEASE['version'],'product_id':'zenai','arch':'amd64','min_version':RELEASE['min_version']},destination=verified)
        if json.loads((verified/'code/migrations.json').read_text()):raise RuntimeError('This installer recipe requires a factory-compatible release with an empty migration ledger.')
        run('systemctl','enable','--now','docker')
        run('docker','load','-i',str(verified/'images/application.tar'))
        if output('docker','image','inspect','--format','{{.Id}}',manifest['image'])!=manifest['image_id']:raise RuntimeError('Loaded image identity differs from the signed manifest')
        for image in RELEASE['dependency_images'].values():run('docker','pull',image)
        BASE.mkdir(mode=0o755,exist_ok=True)
        for name in ('compose.yaml','nginx.conf','firewall.sh','native_setup.py'):
            shutil.copyfile(HERE/name,BASE/name)
        shutil.copyfile(verified/'code/initialize.py',BASE/'initialize.py')
        control=BASE/'appliance/control';control.mkdir(parents=True,exist_ok=True)
        for name in ('agent.py','cli.py','rpc.py'):shutil.copyfile(verified/'code/control'/name,control/name)
        ota=BASE/'appliance/ota';ota.mkdir(parents=True,exist_ok=True)
        for path in (verified/'code/ota').glob('*.py'):shutil.copyfile(path,ota/path.name)
        shutil.copyfile(verified/'code/ota_entry.py',BASE/'appliance/ota_entry.py')
        (BASE/'scripts').mkdir(exist_ok=True);shutil.copyfile(HERE/'install-updater.sh',BASE/'scripts/install-updater.sh')
        write(BASE/'.version',manifest['version']+'\n')
    if subprocess.run(['id','zenadmin'],capture_output=True).returncode:run('useradd','--create-home','--shell','/bin/bash','zenadmin')
    library=Path('/usr/local/lib/zenshield');library.mkdir(parents=True,exist_ok=True)
    for path in control.glob('*.py'):shutil.copyfile(path,library/path.name)
    # The management agent starts the licence worker at boot. Install its
    # verified OTA modules before systemd can start it during a fresh install.
    (library/'ota').mkdir(exist_ok=True)
    for path in ota.glob('*.py'):shutil.copyfile(path,library/'ota'/path.name)
    console_access()
    for path in (HERE/'units').glob('*'):shutil.copyfile(path,Path('/etc/systemd/system')/path.name)
    write('/usr/local/bin/zenshield','#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/zenshield/cli.py "$@"\n',0o755)
    write('/usr/local/sbin/zenshield-setup','#!/bin/sh\nexec /usr/bin/python3 /opt/zensheild/native_setup.py "$@"\n',0o755)
    with Path('/etc/shells').open('a') as f:
        if '/usr/local/bin/zenshield' not in Path('/etc/shells').read_text():f.write('/usr/local/bin/zenshield\n')
    run('usermod','--shell','/usr/local/bin/zenshield','zenadmin')
    write('/etc/sudoers.d/zensheild-admin','zenadmin ALL=(ALL:ALL) ALL\n',0o440);run('visudo','-c')
    write('/etc/ssh/sshd_config.d/90-zenshield-console.conf','Match User zenadmin\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\nMatch all\n')
    # Ubuntu socket activation may leave this runtime directory absent until
    # the first connection starts ssh.service. Validate safely in either mode.
    run('install','-d','-o','root','-g','root','-m','0755','/run/sshd')
    run('sshd','-t');run('systemctl','reload-or-restart','ssh')
    write('/etc/issue','\nZenShield security appliance | Authorized administration only\nManagement address: \\4\n')
    write('/etc/motd','ZenShield '+RELEASE['version']+'\nUse sudo zenshield or sudo zenshield-setup.\n')
    (BASE/'firewall.sh').chmod(0o755)
    write('/etc/apt/apt.conf.d/52zensheild','APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Automatic-Reboot "false";\n')
    write('/etc/fail2ban/jail.d/zensheild.conf','[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nbantime = 3600\n')
    for port in ('80/tcp','443/tcp','514/udp'):run('ufw','allow',port)
    # Preserve existing owner SSH access, including a nonstandard SSH port.
    for line in output('sshd','-T').splitlines():
        if line.startswith('port '):run('ufw','allow',line.split()[1]+'/tcp')
    run('ufw','--force','enable')
    run('systemctl','daemon-reload')
    run('systemctl','enable','--now','chrony','auditd','fail2ban','zenshield-agent')
    run('systemctl','enable','zensheild','zensheild-firewall','zensheild-firstboot')
    Path('/etc/systemd/system/zensheild.service.d').mkdir(exist_ok=True)
    run('bash',str(BASE/'scripts/install-updater.sh'),env=env,cwd=BASE)
    sys.path.insert(0,str(library))
    from ota.common import CONFIG,DEFAULT,write as atomic_write
    c=json.loads(CONFIG.read_text());c['contract_confirmed']=True;atomic_write(CONFIG,c)
    shutil.copyfile(HERE/'release.pub','/etc/zenshield-updater/release.pub');Path('/etc/zenshield-updater/release.pub').chmod(0o644)
    write(STATE/'complete',RELEASE['version']+'\n',0o600)
    print('ZenShield installed from verified release '+RELEASE['version']+'.')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('Run the installer with sudo')
    if args.check:preflight();return
    lock=Path('/run/zenshield-install.lock').open('w')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise RuntimeError('Another ZenShield installer is running')
    install()
    if not Path('/var/lib/zenshield/setup-complete').exists():
        tty=os.open('/dev/tty',os.O_RDWR)
        try:run('/usr/local/sbin/zenshield-setup',stdin=tty,stdout=tty,stderr=tty)
        finally:os.close(tty)
if __name__=='__main__':
    try:main()
    except Exception as e:print('Installation stopped: '+str(e)+'. Existing instance data is retained; resolve the issue and rerun the installer.',file=sys.stderr);raise SystemExit(1)
