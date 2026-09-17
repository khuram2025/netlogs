"""Apply host-backed storage reporting to both full and incremental appliance builds."""
import ast
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1])
control = Path(__file__).resolve().parents[1] / 'appliance/control'
shutil.copyfile(control / 'storage_monitor.py', root / 'fastapi_app/api/storage_monitor.py')
shutil.copyfile(control / 'system.html', root / 'fastapi_app/templates/system/appliance.html')
shutil.copyfile(control / '_ntp_panel.html', root / 'fastapi_app/templates/system/_ntp_panel.html')
shutil.copyfile(control / 'api.py', root / 'fastapi_app/api/appliance.py')
p = root / 'fastapi_app/api/views.py'
s = p.read_text()
tree = ast.parse(s)
lines = s.splitlines(keepends=True)
for node in sorted((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {'get_disk_usage', 'get_system_partitions'}), key=lambda n: n.lineno, reverse=True):
    lines[node.lineno-1:node.end_lineno] = [f'from .storage_monitor import {node.name}\n']
s = ''.join(lines)
# A missing host agent must render an explicit unknown state, never repeat the failing call or fake container capacity.
s = s.replace('"disk_info": get_disk_usage(\'/\'),', '"disk_info": {"total_bytes": 0, "used_bytes": 0, "free_bytes": 0, "total_gb": "—", "used_gb": "—", "free_gb": "—", "usage_percent": 0},')
# Installed appliance paths, with no host-specific developer virtualenv assumptions.
s = s.replace("'/home/net/zentryc/venv/bin/python'", "'/usr/local/bin/python'").replace("cwd='/home/net/zentryc'", "cwd='/app'")
s = s.replace('        # Update allowed fields', '''        from .storage_monitor import validate_settings
        try:
            validate_settings(body, settings)
        except ValueError as exc:
            return JSONResponse({"success": False, "error": str(exc)}, status_code=400)
        # Update allowed fields''')
ast.parse(s)
p.write_text(s)
p = root / 'fastapi_app/templates/system/system_monitor.html'
s = p.read_text().replace('Host filesystem not mounted. Restart the web container to enable partition detection.', 'Host storage service is unavailable. Check appliance services from the console.')
s = s.replace('Disk information unavailable. Mount host filesystem to enable detection.', 'Host disk information is unavailable. Check appliance services from the console.')
s = s.replace('System Monitor', 'Storage Monitor').replace('Disk Usage</', 'Data Filesystem Usage</')
s = s.replace('id="syslogsMaxSize" min="10" max="10000" step="10"', 'id="syslogsMaxSize" min="0.1" step="0.1"')
s = s.replace("settings.syslogs_max_size_gb < 10", "!Number.isFinite(settings.syslogs_max_size_gb) || settings.syslogs_max_size_gb <= 0").replace('Max size must be at least 10 GB', 'Max size must be a positive number')
s = s.replace('<div class="tab-panel" id="tab-quota">', '<div class="tab-panel" id="tab-quota"><p id="quota-capacity-note">A log quota is a retention setting, not allocated disk space. Available capacity is limited by the data filesystem shown above.</p>')
s = s.replace("document.getElementById('freeQuotaDisplay').textContent = q.free_quota_gb.toFixed(2);", "document.getElementById('freeQuotaDisplay').textContent = Math.max(0, q.free_quota_gb).toFixed(2);\n    const note=document.getElementById('quota-capacity-note'); if(note && data.disk) note.textContent=q.max_size_gb > data.disk.total_gb ? 'The configured log quota exceeds the data filesystem capacity. Lower the quota or expand storage; changing the quota does not add disk space.' : 'A log quota controls retention. It does not allocate disk space; other data shares this filesystem.';")
s = s.replace('<!-- ============================================================\n     TAB: PARTITIONS', '<!-- ============================================================\n     TAB: PARTITIONS')
s = s.replace('<div class="tab-panel" id="tab-partitions">', '<div class="tab-panel" id="tab-partitions"><p>Physical disk capacity and mounted filesystem capacity are different. Use <a href="/system/">System → Storage</a> to rescan disks, grow the system filesystem, or extend data volumes.</p>')
p.write_text(s)
cleanup = root / 'fastapi_app/cli/disk_cleanup.py'
if cleanup.exists():
    text = cleanup.read_text().replace('/home/net/zentryc/logs/disk_cleanup.log', '/app/logs/disk_cleanup.log')
    tree = ast.parse(text); lines = text.splitlines(keepends=True)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'get_disk_usage':
            lines[node.lineno-1:node.end_lineno] = ['from fastapi_app.api.storage_monitor import get_disk_usage\n']
            break
    cleanup.write_text(''.join(lines))
print('Applied host storage metrics and management UI')
