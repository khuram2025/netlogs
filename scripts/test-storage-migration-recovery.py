"""Test migration rollback and retry against retained data on the disposable VM only."""
import importlib.util
import fcntl
from pathlib import Path
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
spec=importlib.util.spec_from_file_location('agent',Path(__file__).resolve().parents[1]/'appliance/control/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
assert hasattr(a,'migration_restart_policy')
lock=(a.STATE/'operation.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
assert all(p['pv_name'] in {'/dev/sdb','/dev/sdc'} for p in a.lvm('pvs') if p['vg_name']==a.VG)
a.run('systemctl','stop','zensheild',timeout=180)
overlay=a.BASE/'compose.storage.yaml'
if overlay.exists():
    (a.STATE/'storage-test-overlay.yaml').write_text(overlay.read_text())
    overlay.unlink()
a.compose('up','-d','--wait','--wait-timeout','300',timeout=360)
original=a.compose
failed=False
def fail_once(*args,**kwargs):
    global failed
    if args[0]=='up' and not failed:
        failed=True
        raise a.Rejected('Injected candidate startup failure')
    return original(*args,**kwargs)
a.compose=fail_once
try:
    a.migrate_storage(print)
    raise AssertionError('Failure injection did not run')
except a.Rejected as exc:
    assert 'Injected' in str(exc)
a.compose=original
assert not overlay.exists()
assert not (a.STATE/'storage-migration.json').exists()
assert 'healthy' in a.compose('ps','--format','json')
print('PASS failed migration restores original data configuration and running services',flush=True)
plan=a.plan_storage({'action':'migrate'});a.execute_storage(plan,print)
a.managed_mount_guard()
assert not (a.STATE/'storage-migration.json').exists()
assert Path('/srv/zenshield/application/logs/storage-acceptance.bin').exists()
print('PASS migration retry activates verified data pool and clears recovery journal',flush=True)
a.run('systemctl','start','zensheild',timeout=360)
