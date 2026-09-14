"""Exercise initialization failure/retry on a dedicated loop disk inside the disposable VM."""
import importlib.util
import json
from pathlib import Path

assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').is_file()
spec=importlib.util.spec_from_file_location('agent',Path(__file__).resolve().parents[1]/'appliance/control/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
a.STATE=Path('/var/lib/zenshield-storage-recovery-test');a.STATE.mkdir(exist_ok=True)
image=a.STATE/'recovery.img';assert not image.exists()
with image.open('wb') as f:f.truncate(2*1024**3)
loop=a.run('losetup','--find','--show',str(image))
a.VG='zs_recovery_test'
a.MOUNTS={r:str(a.STATE/r) for r in ('clickhouse','application')}
real_run=a.run
def require(path):
    assert path==loop
    return {'path':loop,'size':2*1024**3,'blank':True}
a.require_disk=require
a.migrate_storage=lambda progress:a.managed_mount_guard()
def failure(*args,**kwargs):
    if args[0]=='mkfs.ext4':raise a.Rejected('Injected interruption before filesystem creation')
    return real_run(*args,**kwargs)
a.run=failure
try:
    a.initialize_storage(loop,print)
    raise AssertionError('Failure injection did not run')
except a.Rejected as e:
    assert 'Injected interruption' in str(e)
a.run=real_run
assert (a.STATE/'storage-initialize.json').exists()
a.complete_staged_pool(print)
a.managed_mount_guard()
print('PASS interrupted initialization resumes only journaled logical volumes',flush=True)
marker=Path(a.MOUNTS['clickhouse'])/'preserved.txt';marker.write_text('preserve staged content')
a.complete_staged_pool(print)
assert marker.read_text()=='preserve staged content'
print('PASS repeated staged recovery does not reformat existing filesystems',flush=True)
stage=json.loads((a.STATE/'storage-initialize.json').read_text());stage['vg_uuid']='different'
(a.STATE/'storage-initialize.json').write_text(json.dumps(stage))
try:
    a.complete_staged_pool(print)
    raise AssertionError('Changed identity accepted')
except a.Rejected:
    assert marker.read_text()=='preserve staged content'
print('PASS changed pool identity rejected without data modification',flush=True)
for role,mount in a.MOUNTS.items():
    a.run('umount',mount);a.run('lvremove','-y',f'/dev/{a.VG}/{role}')
a.run('vgremove','-y',a.VG);a.run('pvremove','-y',loop);a.run('losetup','-d',loop)
image.unlink()
