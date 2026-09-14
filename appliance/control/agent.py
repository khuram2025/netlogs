#!/usr/bin/python3
"""ZenShield host-management service. Fixed operations; never arbitrary commands."""
import fcntl
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socketserver
import socket
import subprocess
import sys
import threading
import time
import uuid
import yaml
from contextlib import contextmanager

BASE = Path('/opt/zensheild')
STATE = Path('/var/lib/zenshield')
SOCKET = '/run/zenshield/agent.sock'
VG = 'zenshield_data'
MOUNTS = {'clickhouse': '/srv/zenshield/clickhouse', 'application': '/srv/zenshield/application'}
LOCK = threading.RLock()
JOBS = {}

class Rejected(ValueError):
    pass

def run(*args, timeout=60, input=None):
    p = subprocess.run(list(args), input=input, text=True, capture_output=True, timeout=timeout,
                       env={**os.environ, 'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    if p.returncode:
        raise Rejected(f'{args[0]} failed: {p.stderr.strip()[-600:] or p.stdout.strip()[-600:]}')
    return p.stdout.strip()

def atomic(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.new')
    tmp.write_text(value)
    tmp.chmod(mode)
    with tmp.open('r+') as f:
        os.fsync(f.fileno())
    tmp.replace(path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)

def record(action, detail):
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / 'audit.jsonl').open('a') as f:
        f.write(json.dumps({'time': time.time(), 'action': action, 'detail': detail}) + '\n')

def compose(*args, timeout=360, input=None):
    command = ['docker', 'compose', '--project-directory', str(BASE), '-f', str(BASE / 'compose.yaml')]
    if (BASE / 'compose.storage.yaml').exists():
        command += ['-f', str(BASE / 'compose.storage.yaml')]
    if (BASE / 'compose.update.yaml').exists():
        command += ['-f', str(BASE / 'compose.update.yaml')]
    return run(*command, *args, timeout=timeout, input=input)

def disks():
    data = json.loads(run('lsblk', '-b', '-J', '-o', 'NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,WWN,RO,RM,MAJ:MIN'))
    answer = []
    for d in data['blockdevices']:
        if d['type'] != 'disk':
            continue
        children = d.get('children', [])
        signatures = json.loads(run('wipefs', '--no-act', '--json', d['path'])).get('signatures', [])
        holders = list((Path('/sys/class/block') / d['name'] / 'holders').iterdir())
        blank = not (children or signatures or holders or d['ro'] or d['rm'] or any(d.get('mountpoints') or []))
        fingerprint = hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()
        answer.append({'path': d['path'], 'size': int(d['size']), 'model': (d.get('model') or '').strip(),
                       'fstype': d.get('fstype') or '', 'children_count': len(children),
                       'serial': d.get('serial') or d.get('wwn') or d['maj:min'], 'blank': blank,
                       'fingerprint': fingerprint, 'reason': 'Available blank disk' if blank else
                       ('LVM pool member' if d.get('fstype') == 'LVM2_member' else 'Partitioned system or data disk; existing data is protected')})
    return answer

def lvm(kind):
    columns = {'vgs': 'vg_name,vg_size,vg_free,vg_missing_pv_count', 'lvs': 'vg_name,lv_name,lv_size,lv_path',
               'pvs': 'pv_name,vg_name,pv_size,pv_free'}
    p = subprocess.run([kind, '--reportformat', 'json', '--units', 'b', '--nosuffix', '-o', columns[kind]],
                       text=True, capture_output=True)
    if p.returncode:
        raise Rejected('LVM inventory is unavailable; storage changes are disabled until it can be read')
    return json.loads(p.stdout)['report'][0][kind[:2]]


def filesystem(path):
    mount = json.loads(run('findmnt', '-J', '-b', '-o', 'SOURCE,TARGET,FSTYPE,OPTIONS', '--target', path))['filesystems'][0]
    usage = shutil.disk_usage(path)
    return {'source': mount['source'], 'mount': mount['target'], 'fstype': mount['fstype'],
            'size': usage.total, 'used': usage.used, 'available': usage.free,
            'usage_percent': round(100 * usage.used / usage.total, 1) if usage.total else 0}


def host_filesystems():
    mounts = json.loads(run('findmnt', '-J', '-l', '-o', 'SOURCE,TARGET,FSTYPE'))['filesystems']
    return [filesystem(m['target']) for m in mounts
            if m['source'].startswith('/dev/') and m['fstype'] in {'ext4', 'xfs', 'vfat', 'btrfs'}
            and not m['target'].startswith(('/var/lib/docker/', '/snap/'))]


def storage_metrics():
    managed = (BASE / 'compose.storage.yaml').exists()
    error = None
    try:
        if managed:
            managed_mount_guard()
            path = MOUNTS['clickhouse']
        else:
            path = run('docker', 'volume', 'inspect', 'zensheild_clickhouse-data', '--format', '{{.Mountpoint}}')
        data = filesystem(path)
    except (Rejected, OSError) as exc:
        data, error = None, str(exc)
    return {'disks': disks(), 'filesystems': host_filesystems(), 'data_filesystem': data,
            'managed': managed, 'data_error': error}


def system_growth():
    """Inspect standard Ubuntu root layouts without modifying disks or filesystems."""
    result = {'supported': False, 'can_grow': False, 'reason': '', 'filesystem': filesystem('/')}
    try:
        fs = result['filesystem']
        if fs['fstype'] not in {'ext4', 'xfs'}:
            raise Rejected('Automatic growth supports ext4 and XFS system filesystems')
        if fs['fstype'] == 'xfs' and not shutil.which('xfs_growfs'):
            raise Rejected('Install the Ubuntu xfsprogs package before growing an XFS filesystem')
        source = os.path.realpath(fs['source'])
        devices = json.loads(run('lsblk', '-b', '-l', '-J', '-o', 'PATH,TYPE,SIZE,PKNAME,RO'))['blockdevices']
        device = next((d for d in devices if os.path.realpath(d['path']) == source), None)
        if not device or device['ro']:
            raise Rejected('The system block device could not be identified safely')
        vg = None
        free = 0
        pv_size = 0
        if device['type'] == 'lvm':
            rows = json.loads(run('lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix', '-o',
                                  'lv_path,vg_name,lv_uuid,lv_size,segtype,lv_attr'))['report'][0]['lv']
            lv = next(v for v in rows if os.path.realpath(v['lv_path']) == source)
            if lv['segtype'] != 'linear' or not lv['lv_attr'].startswith('-') or lv['vg_name'] == VG:
                raise Rejected('This logical-volume layout requires administrator maintenance')
            vg = lv['vg_name']
            members = [p for p in lvm('pvs') if p['vg_name'] == vg]
            if len(members) != 1:
                raise Rejected('Automatic system growth requires a single physical volume in the system group')
            pv = members[0]
            pv_size = int(float(pv['pv_size']))
            free = int(float(next(v for v in lvm('vgs') if v['vg_name'] == vg)['vg_free']))
            backing = next(d for d in devices if os.path.realpath(d['path']) == os.path.realpath(pv['pv_name']))
            result.update(lv=lv['lv_path'], lv_uuid=lv['lv_uuid'], vg=vg, pv=pv['pv_name'])
        else:
            backing = device
        partition_growth = 0
        if backing['type'] == 'part':
            disk = '/dev/' + backing['pkname'].removeprefix('/dev/')
            table = json.loads(run('sfdisk', '--json', disk))['partitiontable']
            parts = table['partitions']
            part = next(p for p in parts if os.path.realpath(p['node']) == os.path.realpath(backing['path']))
            if table['label'] not in {'gpt', 'dos'} or part != max(parts, key=lambda p: p['start'] + p['size']):
                raise Rejected('Only the last physical partition can be expanded automatically')
            number = int((Path('/sys/class/block') / Path(os.path.realpath(backing['path'])).name / 'partition').read_text())
            physical = int(next(d for d in devices if d['path'] == disk)['size'])
            sector = int(table.get('sectorsize', 512))
            # Leave partition-table/alignment room; growpart calculates the exact final sector.
            partition_growth = max(0, physical - (part['start'] + part['size']) * sector - 1024**2)
            if partition_growth < 4 * 1024**2:
                partition_growth = 0
            result.update(disk=disk, partition=number, partition_start=part['start'],
                          partition_size=part['size'], table_id=table.get('id'), disk_size=physical)
        elif backing['type'] == 'disk' and vg:
            result.update(disk=backing['path'], disk_size=int(backing['size']))
        else:
            raise Rejected('This system disk layout requires administrator maintenance')
        result['needs_growpart'] = bool(partition_growth and not shutil.which('growpart'))
        capacity = free + partition_growth
        if vg:
            capacity += max(0, int(backing['size']) - pv_size - 4 * 1024**2)
        repair = False
        if fs['fstype'] == 'ext4':
            header = run('dumpe2fs', '-h', fs['source'])
            count = int(re.search(r'^Block count:\s+(\d+)', header, re.M)[1])
            block = int(re.search(r'^Block size:\s+(\d+)', header, re.M)[1])
            repair = int(device['size']) - count * block >= 4 * 1024**2
        result.update(supported=True, can_grow=capacity >= 4 * 1024**2 or repair, additional_bytes=capacity,
                      block_size=int(device['size']), partition_growth=partition_growth,
                      reason='Unused capacity can be allocated to the system filesystem' if capacity >= 4 * 1024**2 or repair
                      else 'System filesystem is allocated; expand its virtual disk, then rescan')
    except (Rejected, StopIteration, KeyError, OSError, ValueError) as exc:
        result['reason'] = str(exc) or 'The system disk layout could not be verified'
    identity = {k: v for k, v in result.items() if k not in {'filesystem', 'reason', 'fingerprint'}}
    result['fingerprint'] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return result


def grow_system(plan, progress):
    layout = system_growth()
    if not layout['can_grow'] or layout['fingerprint'] != plan['fingerprint']:
        raise Rejected('System storage changed. Rescan and create a new plan.')
    if layout.get('partition_growth'):
        if layout.get('needs_growpart'):
            progress('Installing the Ubuntu partition growth utility')
            run('apt-get', 'install', '-y', '--no-install-recommends', 'cloud-guest-utils', timeout=600)
        progress('Backing up the partition table and expanding the existing system partition')
        atomic(STATE / 'partition-backups' / (str(time.time_ns()) + '.sfdisk'), run('sfdisk', '--dump', layout['disk']))
        run('growpart', layout['disk'], str(layout['partition']))
        run('udevadm', 'settle')
    source = layout['filesystem']['source']
    if layout.get('vg'):
        progress('Refreshing the system physical volume and allocating unused group capacity')
        run('pvresize', layout['pv'])
        free = int(float(next(v for v in lvm('vgs') if v['vg_name'] == layout['vg'])['vg_free']))
        if free:
            run('lvextend', '-y', '-l', '+100%FREE', layout['lv'])
        source = layout['lv']
    progress('Growing the system filesystem online')
    if layout['filesystem']['fstype'] == 'ext4':
        run('resize2fs', source, timeout=600)
    else:
        run('xfs_growfs', '/', timeout=600)
    if filesystem('/')['size'] <= layout['filesystem']['size']:
        raise Rejected('Filesystem capacity did not increase; inspect the retained operation log before retrying')


def rescan_disks(progress):
    progress('Discovering attached disks and refreshing device capacities')
    for scan in Path('/sys/class/scsi_host').glob('host*/scan'):
        scan.write_text('- - -\n')
    for scan in Path('/sys/class/block').glob('*/device/rescan'):
        scan.write_text('1\n')
    for scan in Path('/sys/class/nvme').glob('nvme*/rescan_controller'):
        scan.write_text('1\n')
    run('udevadm', 'settle', '--timeout=30')
    for pv in [p for p in lvm('pvs') if p['vg_name'] == VG]:
        if not re.fullmatch(r'/dev/(sd[a-z]+|vd[a-z]+|nvme\d+n\d+)', pv['pv_name']):
            raise Rejected('Only whole managed disks can be rescanned automatically')
        progress('Refreshing pool capacity on ' + pv['pv_name'])
        run('pvresize', pv['pv_name'])

def storage():
    groups = [v for v in lvm('vgs') if v['vg_name'] == VG]
    volumes = []
    for lv in lvm('lvs'):
        if lv['vg_name'] != VG or lv['lv_name'] not in MOUNTS:
            continue
        path = MOUNTS[lv['lv_name']]
        mounted = os.path.ismount(path)
        usage = shutil.disk_usage(path) if mounted else None
        volumes.append({'name': lv['lv_name'], 'size': int(float(lv['lv_size'])), 'mount': path,
                        'mounted': mounted, 'used': usage.used if usage else 0,
                        'available': usage.free if usage else 0})
    return {'pool': groups[0] if groups else None, 'volumes': volumes,
            'system': system_growth(), **storage_metrics(),
            'physical_volumes': [p for p in lvm('pvs') if p['vg_name'] == VG],
            'managed': (BASE / 'compose.storage.yaml').exists(),
            'initialization_pending': (STATE / 'storage-initialize.json').exists(),
            'jobs': list(JOBS.values())[-10:]}

def interfaces():
    return [i for i in json.loads(run('ip', '-j', 'address'))
            if (Path('/sys/class/net') / i['ifname'] / 'device').exists()]

def status():
    return {'product': 'ZenShield', 'version': (BASE / '.version').read_text().strip() if (BASE / '.version').exists() else '0.2.0', 'hostname': run('hostname'),
            'uptime_seconds': float(Path('/proc/uptime').read_text().split()[0]),
            'interfaces': interfaces(), 'routes': json.loads(run('ip', '-j', 'route')),
            'dns': run('resolvectl', 'dns'), 'timezone': run('timedatectl', 'show', '-p', 'Timezone', '--value'),
            'services': compose('ps', '--format', 'json') if (BASE / '.env').exists() else '', 'setup_complete': (STATE / 'setup-complete').exists(),
            'network_pending': pending_network(public=True)}

def require_disk(path):
    # Whole-device paths only, including virtio, SCSI and NVMe.
    if not isinstance(path, str) or not re.fullmatch(r'/dev/(sd[a-z]+|vd[a-z]+|nvme\d+n\d+)', path):
        raise Rejected('Select a whole disk from the discovered inventory')
    d = next((d for d in disks() if d['path'] == path), None)
    if not d or not d['blank']:
        raise Rejected('Disk is not blank. System disks and existing data cannot be initialized.')
    return d


DATA_MAPPING = {'clickhouse-data': ('clickhouse', ''), 'postgres-data': ('application', 'postgres'),
                'redis-data': ('application', 'redis'), 'app-logs': ('application', 'logs'),
                'app-credentials': ('application', 'credentials')}


def source_data():
    sources, sizes = {}, dict.fromkeys(MOUNTS, 0)
    for volume, (role, directory) in DATA_MAPPING.items():
        source = run('docker', 'volume', 'inspect', 'zensheild_' + volume, '--format', '{{.Mountpoint}}')
        if not source.startswith('/var/lib/docker/volumes/zensheild_') or not source.endswith('/_data'):
            raise Rejected('Unexpected source data volume; migration requires the original appliance volumes')
        sources[volume] = source
        sizes[role] += int(run('du', '-s', '--apparent-size', '-B1', source, timeout=180).split()[0])
    return sources, sizes


def allocation_sizes(capacity):
    _, used = source_data()
    mib = 1024**2
    usable = (capacity - 16 * mib) // mib
    minimum = {role: max(128, (int(size * 1.15) + 128 * mib + mib - 1) // mib) for role, size in used.items()}
    if usable < sum(minimum.values()):
        raise Rejected('This disk cannot hold the existing data plus filesystem overhead and copy headroom. Add a larger blank disk.')
    spare = usable - sum(minimum.values())
    return {'clickhouse': minimum['clickhouse'] + int(spare * .70),
            'application': minimum['application'] + int(spare * .20)}

def plan_storage(body):
    action = body.get('action')
    s = storage()
    if action not in {'rescan', 'grow-system'} and s['pool'] and int(s['pool'].get('vg_missing_pv_count', 0)):
        raise Rejected('A pool disk is missing. Reattach every pool disk and rescan before changing storage.')
    plan = {'action': action, 'expires': time.time() + 300}
    if action in {'initialize', 'add-disk'}:
        disk = require_disk(body.get('disk'))
        if action == 'initialize' and s['pool']:
            raise Rejected('Storage pool already exists; add the disk instead')
        if action == 'add-disk' and not s['pool']:
            raise Rejected('Initialize the storage pool first')
        plan.update(disk=disk['path'], fingerprint=disk['fingerprint'])
        if action == 'initialize':
            plan['allocation_mib'] = allocation_sizes(disk['size'])
        plan['confirmation'] = f"INITIALIZE {disk['path']}" if action == 'initialize' else f"ADD {disk['path']}"
        plan['summary'] = ('Create an expandable pool and move ClickHouse and application data. Services pause during the copy; original volumes are retained.'
                           if action == 'initialize' else 'Add this blank disk to the existing storage pool. All pool disks must remain attached.')
    elif action == 'grow':
        name = body.get('volume')
        lv = next((v for v in s['volumes'] if v['name'] == name), None)
        try:
            size = int(body.get('size_gib', 0))
        except (TypeError, ValueError):
            raise Rejected('Enter a whole-number target size in GiB')
        if not lv or size <= 0 or size > 1024 * 1024:
            raise Rejected('Select a managed volume and valid target size')
        target = size * 1024**3
        if target < lv['size']:
            raise Rejected('Only growth is supported. Shrinking requires an offline backup and migration.')
        free = int(float(s['pool']['vg_free']))
        if target - lv['size'] > free:
            raise Rejected('Not enough free pool space. Add or expand a data disk first.')
        plan.update(volume=name, size_gib=size, current_size=lv['size'], confirmation=f'GROW {name} TO {size} GiB',
                    summary='Extend the logical volume and ext4 filesystem online. Existing data remains in place.')
    elif action == 'grow-system':
        layout = s['system']
        if not layout['can_grow']:
            raise Rejected(layout['reason'])
        plan.update(fingerprint=layout['fingerprint'], confirmation='GROW SYSTEM FILESYSTEM',
                    summary='Expand the existing system partition and filesystem in place. For LVM, allocate all unused space in the system volume group to the root volume. Existing data and other logical volumes are retained. If required, install the Ubuntu cloud-guest-utils package from the configured Ubuntu repositories.')
    elif action == 'rescan':
        plan.update(confirmation='RESCAN DISKS', summary='Discover newly attached disks and refresh managed pool capacity. This does not format disks or allocate system filesystem space.')
    elif action == 'migrate':
        if not s['pool'] or s['managed']:
            raise Rejected('Migration recovery requires an existing pool that is not yet active')
        plan.update(confirmation='RETRY DATA MIGRATION', summary='Retry the verified copy from the original application volumes into the staged data pool. Services pause during the copy; original volumes are retained.')
    else:
        raise Rejected('Unsupported storage action')
    token = secrets.token_urlsafe(24)
    atomic(STATE / 'plans' / (token + '.json'), json.dumps(plan))
    return {**plan, 'token': token}

def storage_guard():
    if not (BASE / 'compose.storage.yaml').exists():
        return
    managed_mount_guard()

def managed_mount_guard():
    for role, path in MOUNTS.items():
        if not os.path.ismount(path):
            raise Rejected(f'{role} data volume is not mounted. Services remain stopped to protect data.')
        source = run('findmnt', '-n', '-o', 'SOURCE', '--target', path)
        if os.path.realpath(source) != os.path.realpath(f'/dev/{VG}/{role}'):
            raise Rejected(f'Unexpected filesystem mounted at {path}')

def initialize_storage(disk, progress):
    require_disk(disk)
    sizes = allocation_sizes(require_disk(disk)['size'])
    progress('Creating storage pool on the confirmed blank disk')
    run('pvcreate', '--yes', disk)
    run('vgcreate', VG, disk)
    stage = {'disk': disk, 'vg_uuid': run('vgs', '--noheadings', '-o', 'vg_uuid', VG).strip(), 'sizes': sizes, 'lvs': {}}
    atomic(STATE / 'storage-initialize.json', json.dumps(stage))
    complete_staged_pool(progress)
    migrate_storage(progress)


def complete_staged_pool(progress):
    marker = STATE / 'storage-initialize.json'
    if not marker.exists():
        return  # Legacy staged pools may already have both verified ext4 volumes.
    stage = json.loads(marker.read_text())
    if run('vgs', '--noheadings', '-o', 'vg_uuid', VG).strip() != stage['vg_uuid']:
        raise Rejected('Staged pool identity changed; refusing to initialize volumes')
    sizes = stage['sizes']
    for role, size in sizes.items():
        dev = f'/dev/{VG}/{role}'
        exists = next((lv for lv in lvm('lvs') if lv['vg_name'] == VG and lv['lv_name'] == role), None)
        if not exists:
            if role in stage['lvs']:
                raise Rejected('A previously created staged volume is missing; manual recovery is required')
            progress(f'Creating {role} volume ({size} MiB)')
            run('lvcreate', '-y', '-L', f'{size}M', '-n', role, VG)
            stage['lvs'][role] = run('lvs', '--noheadings', '-o', 'lv_uuid', dev).strip()
            atomic(marker, json.dumps(stage))
        if stage['lvs'].get(role) != run('lvs', '--noheadings', '-o', 'lv_uuid', dev).strip():
            raise Rejected('Unrecognized staged logical volume; refusing to format existing data')
        signatures = json.loads(run('wipefs', '--no-act', '--json', dev)).get('signatures', [])
        if not signatures:
            run('mkfs.ext4', '-q', '-m', '1', '-L', 'ZenShield-' + role[:5], dev, timeout=180)
        elif run('blkid', '-s', 'TYPE', '-o', 'value', dev) != 'ext4':
            raise Rejected('Unexpected filesystem on the staged data volume')
        Path(MOUNTS[role]).mkdir(parents=True, exist_ok=True)
        if not os.path.ismount(MOUNTS[role]):
            run('mount', '-o', 'nodev,nosuid', dev, MOUNTS[role])

def migrate_storage(progress):
    for role, path in MOUNTS.items():
        if not os.path.ismount(path):
            device = f'/dev/{VG}/{role}'
            if run('blkid', '-s', 'TYPE', '-o', 'value', device) != 'ext4':
                raise Rejected('Migration recovery requires the expected ext4 data volumes')
            Path(path).mkdir(parents=True, exist_ok=True)
            run('mount', '-o', 'nodev,nosuid', device, path)
    managed_mount_guard()
    sources, used = source_data()
    for role, size in used.items():
        if size + 64 * 1024**2 > shutil.disk_usage(MOUNTS[role]).total * .97:
            raise Rejected(f'{role} data will not fit. Extend the staged volume before retrying migration; original data remains active.')
    progress('Stopping services for a consistent copy')
    previous = (BASE / 'compose.storage.yaml').read_text() if (BASE / 'compose.storage.yaml').exists() else None
    atomic(STATE / 'storage-migration.json', json.dumps({'previous_overlay': previous}))
    try:
        migration_restart_policy('no')
        compose('stop', timeout=180)
        for volume, (role, directory) in DATA_MAPPING.items():
            destination = Path(MOUNTS[role]) / directory
            destination.mkdir(parents=True, exist_ok=True)
            source = sources[volume]
            progress('Copying ' + volume)
            run('rsync', '-aHAX', '--delete', '--exclude=/lost+found', '--numeric-ids', source + '/', str(destination) + '/', timeout=1800)
            mismatch = run('rsync', '-aHAXnc', '--delete', '--exclude=/lost+found', '--numeric-ids', '--out-format=%n', source + '/', str(destination) + '/', timeout=1800)
            if mismatch:
                raise Rejected('Data copy verification failed for ' + volume)
        overlay = {'services': {
            'postgres': {'volumes': ['/srv/zenshield/application/postgres:/var/lib/postgresql/data']},
            'redis': {'volumes': ['/srv/zenshield/application/redis:/data']},
            'clickhouse': {'volumes': ['/srv/zenshield/clickhouse:/var/lib/clickhouse']},
            'web': {'volumes': ['/srv/zenshield/application/logs:/app/logs', '/srv/zenshield/application/credentials:/app/data/credentials']},
            'syslog': {'volumes': ['/srv/zenshield/application/logs:/app/logs']}}}
        for service in ('web', 'syslog', 'clickhouse', 'postgres', 'redis', 'nginx'):
            overlay['services'].setdefault(service, {})['restart'] = 'no'
        atomic(BASE / 'compose.storage.yaml', yaml.safe_dump(overlay))
        fstab = Path('/etc/fstab').read_text()
        for role, path in MOUNTS.items():
            fsuuid = run('blkid', '-s', 'UUID', '-o', 'value', f'/dev/{VG}/{role}')
            if not any(line.split()[1:2] == [path] for line in fstab.splitlines() if not line.startswith('#')):
                fstab += f'\nUUID={fsuuid} {path} ext4 defaults,nodev,nosuid,x-systemd.device-timeout=30s 0 2\n'
        atomic('/etc/fstab', fstab, 0o644)
        run('systemctl', 'daemon-reload')
        storage_guard()
        progress('Starting services on verified managed storage')
        compose('up', '-d', '--wait', '--wait-timeout', '300', timeout=360)
        for config in overlay['services'].values():
            config.pop('restart', None)
        atomic(BASE / 'compose.storage.yaml', yaml.safe_dump(overlay))
        (STATE / 'storage-migration.json').unlink(missing_ok=True)
        migration_restart_policy('unless-stopped')
        (STATE / 'storage-initialize.json').unlink(missing_ok=True)
    except Exception:
        # Never delete either copy. Restore service configuration on failure.
        if previous is None:
            (BASE / 'compose.storage.yaml').unlink(missing_ok=True)
        else:
            atomic(BASE / 'compose.storage.yaml', previous)
        compose('up', '-d', '--wait', '--wait-timeout', '300', timeout=360)
        (STATE / 'storage-migration.json').unlink(missing_ok=True)
        migration_restart_policy('unless-stopped')
        raise


def migration_restart_policy(policy):
    for service in ('web', 'syslog', 'clickhouse', 'postgres', 'redis', 'nginx'):
        run('docker', 'update', '--restart=' + policy, 'zensheild-' + service + '-1')


def recover_interrupted_migration():
    marker = STATE / 'storage-migration.json'
    if not marker.exists():
        return
    # A reboot during copying must restart the retained original data, never a partial destination.
    previous = json.loads(marker.read_text())['previous_overlay']
    if previous is None:
        (BASE / 'compose.storage.yaml').unlink(missing_ok=True)
    else:
        atomic(BASE / 'compose.storage.yaml', previous)
    record('storage.migration-recovered', {'message': 'Restored previous data configuration; staged copy retained for retry'})

def execute_storage(plan, progress):
    if plan['action'] in {'initialize', 'add-disk'}:
        current = require_disk(plan['disk'])
        if current['fingerprint'] != plan['fingerprint']:
            raise Rejected('Disk inventory changed. Create a new plan.')
    if plan['action'] == 'initialize':
        initialize_storage(plan['disk'], progress)
    elif plan['action'] == 'migrate':
        if (BASE / 'compose.storage.yaml').exists(): raise Rejected('Managed storage is already active')
        complete_staged_pool(progress)
        migrate_storage(progress)
    elif plan['action'] == 'add-disk':
        progress('Adding blank disk to storage pool')
        run('pvcreate', '--yes', plan['disk'])
        run('vgextend', VG, plan['disk'])
    elif plan['action'] == 'grow':
        fresh = plan_storage({'action': 'grow', 'volume': plan['volume'], 'size_gib': plan['size_gib']})
        (STATE / 'plans' / (fresh['token'] + '.json')).unlink()
        path = MOUNTS[plan['volume']]
        dev = f"/dev/{VG}/{plan['volume']}"
        if not os.path.ismount(path) or os.path.realpath(run('findmnt', '-n', '-o', 'SOURCE', '--target', path)) != os.path.realpath(dev):
            raise Rejected('The expected data volume must be mounted before it can be expanded')
        progress('Extending logical volume and filesystem')
        if fresh['size_gib'] * 1024**3 > fresh['current_size']:
            run('lvextend', '-y', '-L', f"{fresh['size_gib']}G", dev, timeout=600)
        # Separate steps allow an interrupted filesystem resize to be retried at the same LV size.
        run('resize2fs', dev, timeout=600)
    elif plan['action'] == 'grow-system':
        grow_system(plan, progress)
    elif plan['action'] == 'rescan':
        rescan_disks(progress)

def commit_storage(body):
    token = body.get('token', '')
    if not re.fullmatch(r'[A-Za-z0-9_-]{20,80}', token):
        raise Rejected('Invalid plan token')
    path = STATE / 'plans' / (token + '.json')
    if not path.exists():
        raise Rejected('Plan does not exist or has already been used')
    plan = json.loads(path.read_text())
    if plan['expires'] < time.time() or body.get('confirmation') != plan['confirmation']:
        raise Rejected('Plan expired or confirmation does not match')
    if any(j['state'] == 'running' for j in JOBS.values()):
        raise Rejected('Another storage operation is running')
    path.unlink()
    jobid = uuid.uuid4().hex
    job = {'id': jobid, 'state': 'running', 'message': 'Starting', 'action': plan['action'], 'started': time.time()}
    JOBS[jobid] = job
    atomic(STATE / 'jobs' / (jobid + '.json'), json.dumps(job))
    def worker():
        def progress(message):
            job['message'] = message
            atomic(STATE / 'jobs' / (jobid + '.json'), json.dumps(job))
        try:
            with (STATE / 'operation.lock').open('w') as f:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                execute_storage(plan, progress)
            job.update(state='completed', message='Storage operation completed')
        except Exception as exc:
            job.update(state='failed', message=str(exc))
        job['finished'] = time.time()
        atomic(STATE / 'jobs' / (jobid + '.json'), json.dumps(job))
        record('storage.' + plan['action'], {'job': jobid, 'state': job['state'], 'message': job['message']})
    threading.Thread(target=worker, daemon=True).start()
    return job

def pending_network(public=False):
    path = STATE / 'network-pending.json'
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return {k: data[k] for k in ('token', 'deadline')} if public else data

def validate_network(data):
    iface = data.get('interface')
    if iface not in [i['ifname'] for i in interfaces()]:
        raise Rejected('Select an existing physical interface')
    dhcp = data.get('dhcp') is True
    cfg = {'dhcp4': dhcp, 'dhcp6': False, 'dhcp-identifier': 'mac'}
    if not dhcp:
        address = ipaddress.IPv4Interface(data.get('address', ''))
        gateway = ipaddress.IPv4Address(data.get('gateway', ''))
        if gateway not in address.network or gateway == address.ip:
            raise Rejected('Gateway must be another address in the same subnet')
        cfg.update(addresses=[str(address)], routes=[{'to': 'default', 'via': str(gateway)}])
    dns = data.get('dns', [])
    if not isinstance(dns, list) or len(dns) > 3:
        raise Rejected('Provide up to three DNS server addresses')
    if dns:
        cfg['nameservers'] = {'addresses': [str(ipaddress.ip_address(x)) for x in dns]}
        if dhcp:
            cfg['dhcp4-overrides'] = {'use-dns': False}
    return iface, cfg

@contextmanager
def network_lock():
    with (STATE / 'network.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield

def rollback_network(expected=None):
    with network_lock():
        return _rollback_network(expected)

def _rollback_network(expected=None):
    pending = pending_network()
    if not pending or (expected is not None and pending['token'] != expected):
        return
    for path in Path('/etc/netplan').glob('*.yaml'):
        path.unlink()
    for name, content in pending['files'].items():
        atomic(Path('/etc/netplan') / name, content)
    run('netplan', 'generate')
    run('netplan', 'apply', timeout=90)
    (STATE / 'network-pending.json').unlink(missing_ok=True)
    record('network.rollback', {})

def apply_network(data):
    if any(j['state'] == 'running' for j in JOBS.values()):
        raise Rejected('Wait for the storage operation to finish before changing networking')
    if pending_network():
        raise Rejected('Confirm or revert the pending network change first')
    iface, config = validate_network(data)
    effective = yaml.safe_load(run('netplan', 'get')) or {}
    network = effective.get('network', {})
    if any(network.get(key) for key in ('bridges', 'bonds', 'vlans', 'wifis', 'tunnels')):
        raise Rejected('Complex network topology requires expert maintenance')
    # Appliance management owns simple physical NIC definitions only.
    ethernets = network.get('ethernets', {})
    for key, value in list(ethernets.items()):
        if key == iface or value.get('match', {}).get('name') in (iface, 'e*'):
            del ethernets[key]
    ethernets[iface] = config
    candidate = {'network': {'version': 2, 'renderer': 'networkd', 'ethernets': ethernets}}
    token = secrets.token_urlsafe(18)
    pending = {'token': token, 'deadline': time.time() + 120,
               'files': {p.name: p.read_text() for p in Path('/etc/netplan').glob('*.yaml')}}
    atomic(STATE / 'network-pending.json', json.dumps(pending))
    try:
        for path in Path('/etc/netplan').glob('*.yaml'):
            path.unlink()
        atomic('/etc/netplan/99-zenshield.yaml', yaml.safe_dump(candidate))
        run('netplan', 'generate')
        run('systemd-run', '--unit=zenshield-net-rollback-' + token[:8], '--on-active=120s', '--timer-property=AccuracySec=1s',
            '/usr/bin/python3', '/usr/local/lib/zenshield/agent.py', 'rollback', token)
    except Exception:
        rollback_network()
        raise
    def apply():
        time.sleep(2)
        try:
            run('netplan', 'apply', timeout=90)
        except Exception:
            rollback_network()
    threading.Thread(target=apply, daemon=True).start()
    record('network.apply', {'interface': iface, 'dhcp': config['dhcp4']})
    return {'token': token, 'deadline': pending['deadline'], 'message': 'Confirm within 120 seconds or the previous network configuration returns.'}

def update_basic(data):
    if 'hostname' in data:
        name = data['hostname']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]', name):
            raise Rejected('Use a lowercase hostname containing letters, digits and hyphens')
        run('hostnamectl', 'set-hostname', name)
        lines = [l for l in Path('/etc/hosts').read_text().splitlines() if not l.startswith('127.0.1.1')]
        atomic('/etc/hosts', '\n'.join(lines) + '\n127.0.1.1 ' + name + '\n', 0o644)
    if 'timezone' in data:
        zone = data['timezone']
        if zone not in run('timedatectl', 'list-timezones').splitlines():
            raise Rejected('Select a valid timezone')
        run('timedatectl', 'set-timezone', zone)
    if 'ntp' in data:
        host = data['ntp']
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', host):
            raise Rejected('Enter an NTP hostname or IP address')
        atomic('/etc/chrony/sources.d/zenshield.sources', f'server {host} iburst\n', 0o644)
        run('systemctl', 'restart', 'chrony')
    record('configuration.update', {k: data[k] for k in ('hostname', 'timezone', 'ntp') if k in data})
    return {'message': 'Appliance settings updated'}

def dispatch(operation, body):
    if isinstance(operation,str) and operation.startswith(('updates.','licences.')):
        from ota.api import dispatch as updates_dispatch
        return updates_dispatch(operation,body)
    if operation not in {'status','storage','storage.metrics','diagnostic.ping'}:
        from ota.common import locked
        with locked('/var/lib/zenshield-updater/update.lock'):
            return dispatch_control(operation,body)
    return dispatch_control(operation,body)

def dispatch_control(operation,body):
    if operation == 'status': return status()
    if operation == 'storage': return storage()
    if operation == 'storage.metrics': return storage_metrics()
    if operation == 'storage.plan': return plan_storage(body)
    if operation == 'storage.commit': return commit_storage(body)
    if operation == 'network.apply': return apply_network(body)
    if operation == 'network.confirm':
        with network_lock():
            p = pending_network()
            if not p or body.get('token') != p['token'] or p['deadline'] < time.time():
                raise Rejected('No matching unexpired network change')
            (STATE / 'network-pending.json').unlink()
        record('network.confirm', {})
        return {'message': 'Network configuration committed'}
    if operation == 'network.rollback':
        rollback_network()
        return {'message': 'Previous network configuration restored'}
    if operation == 'settings.update': return update_basic(body)
    if operation == 'password.gui':
        password = body.get('password')
        if not isinstance(password, str) or len(password) < 5 or len(password.encode()) > 72 or any(c in password for c in '\r\n\x00'):
            raise Rejected('Use a password of at least 5 characters and at most 72 UTF-8 bytes without line breaks')
        output = compose('exec', '-T', 'web', 'python', '/app/zenshield_reset_password.py',
                         input=json.dumps({'password': password}), timeout=60)
        record('password.gui', {'account': 'admin'})
        return json.loads(output)
    if operation == 'service.restart':
        name = body.get('service')
        if name not in {'web', 'syslog', 'nginx', 'postgres', 'clickhouse', 'redis'}:
            raise Rejected('Unknown appliance service')
        compose('restart', name)
        record('service.restart', {'service': name})
        return {'message': name + ' restarted'}
    if operation == 'diagnostic.ping':
        target = body.get('target', '')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', target):
            raise Rejected('Enter a hostname or IP address')
        return {'output': run('ping', '-c', '4', '-W', '2', '--', target, timeout=15)}
    raise Rejected('Unsupported operation')

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        status_code = 200
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if size < 2 or size > 16384 or self.path != '/rpc':
                raise Rejected('Invalid management request')
            request = json.loads(self.rfile.read(size))
            if not isinstance(request, dict) or not isinstance(request.get('body', {}), dict):
                raise Rejected('Invalid request body')
            with LOCK:
                result = dispatch(request.get('operation'), request.get('body', {}))
        except (ValueError, Rejected, KeyError) as exc:
            status_code, result = 400, {'error': str(exc)}
        except Exception as exc:
            status_code, result = 500, {'error': 'Operation failed; inspect the appliance maintenance log'}
            record('error', {'type': type(exc).__name__, 'message': str(exc)[:600]})
        encoded = json.dumps(result).encode()
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

def main():
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) > 1:
        if sys.argv[1] == 'rollback': rollback_network(sys.argv[2] if len(sys.argv) > 2 else None)
        elif sys.argv[1] == 'start-services':
            recover_interrupted_migration()
            storage_guard()
            compose('up', '-d', '--wait', '--wait-timeout', '300', timeout=360)
            if (STATE / 'storage-migration.json').exists():
                (STATE / 'storage-migration.json').unlink()
                migration_restart_policy('unless-stopped')
        elif sys.argv[1] == 'stop-services': compose('stop')
        return
    if pending_network(): rollback_network()
    for p in (STATE / 'jobs').glob('*.json'):
        job = json.loads(p.read_text())
        if job.get('state') == 'running':
            job.update(state='interrupted', message='Operation interrupted by restart; inspect storage before retrying')
        JOBS[job['id']] = job
    Path(SOCKET).parent.mkdir(parents=True, exist_ok=True)
    Path(SOCKET).unlink(missing_ok=True)
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o660)
        os.chown(SOCKET, 0, 1000)
        from ota.transport import licence_background
        threading.Thread(target=licence_background,daemon=True).start()
        notify = os.environ.get('NOTIFY_SOCKET')
        if notify:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as ready:
                ready.sendto(b'READY=1', '\0' + notify[1:] if notify.startswith('@') else notify)
        server.serve_forever()

if __name__ == '__main__': main()
