"""Destructive storage acceptance ONLY on explicitly attached disposable test disks.

Run as root on the marked native-install test VM; never on a customer appliance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').is_file()
spec = importlib.util.spec_from_file_location('storage_agent', Path(__file__).resolve().parents[1] / 'appliance/control/agent.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
a.STATE = Path('/var/lib/zenshield-storage-test')
a.STATE.mkdir(exist_ok=True)
report = []


def check(name, condition):
    assert condition, name
    report.append(name)
    print('PASS ' + name, flush=True)


def execute(body):
    plan = a.plan_storage(body)
    a.execute_storage(plan, lambda text: print(text, flush=True))
    return plan


def root_lvm():
    # This disk was newly created for this task and its expected size is checked before any write.
    disk = a.require_disk('/dev/sdb')
    assert disk['size'] == 24 * 1024**3
    a.run('sfdisk', '/dev/sdb', input='label: gpt\n,8G,L\n')
    a.run('udevadm', 'settle')
    a.run('pvcreate', '/dev/sdb1')
    a.run('vgcreate', 'zs_storage_test', '/dev/sdb1')
    a.run('lvcreate', '-L', '4G', '-n', 'root', 'zs_storage_test')
    a.run('mkfs.ext4', '-q', '/dev/zs_storage_test/root')
    mount = Path('/mnt/zenshield-root-test'); mount.mkdir(exist_ok=True)
    a.run('mount', '/dev/zs_storage_test/root', str(mount))
    marker = mount / 'preserve.bin'; marker.write_bytes(os.urandom(1024**2))
    digest = hashlib.sha256(marker.read_bytes()).hexdigest()
    original = a.filesystem
    a.filesystem = lambda path: original(str(mount) if path == '/' else path)
    before = a.filesystem('/')['size']
    plan = a.plan_storage({'action': 'grow-system'})
    a.execute_storage(plan, print)
    after = a.filesystem('/')['size']
    check('Ubuntu LVM root: partition + PV + LV + ext4 grew from 4 GiB to disk capacity', after > 22 * 1024**3 and after > before)
    check('Root data checksum retained after growth', hashlib.sha256(marker.read_bytes()).hexdigest() == digest)
    check('Fully allocated root does not offer redundant growth', not a.system_growth()['can_grow'])
    a.filesystem = original
    a.run('umount', str(mount))
    a.run('lvremove', '-y', '/dev/zs_storage_test/root')
    a.run('vgremove', '-y', 'zs_storage_test')
    a.run('pvremove', '-y', '/dev/sdb1')
    a.run('wipefs', '-a', '/dev/sdb1')
    a.run('wipefs', '-a', '/dev/sdb')
    a.run('udevadm', 'settle')
    check('Test disk returned to blank inventory', a.require_disk('/dev/sdb')['blank'])


def pool():
    check('System disk cannot be initialized', not next(d for d in a.disks() if d['path'] == '/dev/sda')['blank'])
    try:
        a.plan_storage({'action': 'initialize', 'disk': '/dev/sda'})
        raise AssertionError('System disk was accepted')
    except a.Rejected:
        check('System disk write rejected by host validation', True)
    original = a.source_data()[0]
    marker = Path(original['app-logs']) / 'storage-acceptance.bin'
    marker.write_bytes(os.urandom(1024**2)); digest = hashlib.sha256(marker.read_bytes()).hexdigest()
    execute({'action': 'rescan'})
    execute({'action': 'initialize', 'disk': '/dev/sdb'})
    a.managed_mount_guard()
    target = Path(a.MOUNTS['application']) / 'logs/storage-acceptance.bin'
    check('Data pool migration preserves checksum and original data', hashlib.sha256(target.read_bytes()).hexdigest() == digest and marker.exists())
    check('Host metrics now report ClickHouse data mount', a.storage_metrics()['data_filesystem']['mount'] == a.MOUNTS['clickhouse'])
    before = int(float(a.storage()['pool']['vg_free']))
    execute({'action': 'add-disk', 'disk': '/dev/sdc'})
    check('Adding a disk increases allocatable pool capacity', int(float(a.storage()['pool']['vg_free'])) > before + 11 * 1024**3)
    s = a.storage(); volume = next(v for v in s['volumes'] if v['name'] == 'clickhouse')
    execute({'action': 'grow', 'volume': 'clickhouse', 'size_gib': (volume['size'] // 1024**3) + 4})
    check('ClickHouse filesystem expands online', a.filesystem(a.MOUNTS['clickhouse'])['size'] > volume['size'])
    try:
        a.plan_storage({'action': 'grow', 'volume': 'clickhouse', 'size_gib': 1})
        raise AssertionError('Shrink was accepted')
    except a.Rejected:
        check('Shrinking is rejected', True)
    check('Data survives pool extension', hashlib.sha256(target.read_bytes()).hexdigest() == digest)
    Path('/var/lib/zenshield-storage-test/checksum').write_text(digest)


if sys.argv[1] == 'initial':
    root_lvm()
    pool()
elif sys.argv[1] == 'expanded':
    a.managed_mount_guard()
    check('Managed mounts survive reboot', True)
    target = Path(a.MOUNTS['application']) / 'logs/storage-acceptance.bin'
    check('Migrated data survives reboot', hashlib.sha256(target.read_bytes()).hexdigest() == (a.STATE / 'checksum').read_text())
    before = int(float(a.storage()['pool']['vg_free']))
    execute({'action': 'rescan'})
    check('Expanded existing disk is fully represented in pool capacity', int(float(a.storage()['pool']['vg_size'])) > 47 * 1024**3)
    if a.system_growth()['can_grow']:
        execute({'action': 'grow-system'})
    check('Expanded Ubuntu root capacity is usable, including cloud-init automatic growth', a.filesystem('/')['size'] > 110 * 1024**3)
elif sys.argv[1] == 'resize-retry':
    lv = next(v for v in a.storage()['volumes'] if v['name'] == 'clickhouse')
    target = lv['size'] // 1024**3 + 1
    old = a.filesystem(a.MOUNTS['clickhouse'])['size']
    a.run('lvextend', '-y', '-L', str(target) + 'G', '/dev/zenshield_data/clickhouse')
    execute({'action': 'grow', 'volume': 'clickhouse', 'size_gib': target})
    check('Interrupted volume growth retries filesystem resize at the same LV size', a.filesystem(a.MOUNTS['clickhouse'])['size'] > old)
else:
    raise SystemExit('Specify initial or expanded')
(a.STATE / ('results-' + sys.argv[1] + '.json')).write_text(json.dumps(report, indent=2))
