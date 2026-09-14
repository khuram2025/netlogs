"""Erase customer data only on an explicitly designated disposable export clone."""
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0,'/usr/local/lib/zenshield')
from agent import BASE, managed_mount_guard

if not Path('/root/ZENSHEILD-DISPOSABLE-EXPORT-CLONE').is_file():
    raise SystemExit('Disposable export clone marker required')
if (BASE/'compose.storage.yaml').exists():
    managed_mount_guard()
    roots=[Path('/srv/zenshield/clickhouse')]+[Path('/srv/zenshield/application')/p for p in ('postgres','redis','logs','credentials')]
    for root in roots:
        if root.is_symlink() or not root.is_dir():raise SystemExit('Unexpected data directory: '+str(root))
        for entry in root.iterdir():
            if entry.name=='lost+found':continue
            if entry.is_symlink() or not entry.is_dir():entry.unlink()
            else:shutil.rmtree(entry)
