"""Real ext4 partition growth with non-sequential partition numbers on a disposable loop disk."""
import importlib.util
from pathlib import Path
assert Path('/root/ZENSHIELD-NATIVE-INSTALL-TEST').exists()
spec=importlib.util.spec_from_file_location('agent',Path(__file__).resolve().parents[1]/'appliance/control/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
a.STATE=Path('/var/lib/zenshield-plain-root-test');a.STATE.mkdir(exist_ok=True)
image=a.STATE/'root.img';assert not image.exists()
with image.open('wb') as f:f.truncate(2*1024**3)
disk=a.run('losetup','--find','--show','--partscan',str(image))
a.run('sfdisk',disk,input=f'label: gpt\n{disk}p1 : start=262144, size=2097152, type=L\n{disk}p2 : start=2048, size=204800, type=L\n')
a.run('partx','-u',disk);a.run('udevadm','settle')
a.run('mkfs.ext4','-q',disk+'p1')
mount=a.STATE/'mount';mount.mkdir(exist_ok=True)
a.run('mount',disk+'p1',str(mount))
marker=mount/'preserve';marker.write_text('preserved plain root')
original=a.filesystem
a.filesystem=lambda path:original(str(mount) if path=='/' else path)
layout=a.system_growth();assert layout['can_grow'],layout
assert layout['partition']==1
plan=a.plan_storage({'action':'grow-system'});a.execute_storage(plan,print)
assert a.filesystem('/')['size']>1800*1024**2
assert marker.read_text()=='preserved plain root'
print('PASS plain ext4 root grows while preserving a later-numbered boot partition and file contents')
a.filesystem=original
a.run('umount',str(mount));a.run('losetup','-d',disk);image.unlink()
