"""Apply the DNS extension to an existing hardened application tree, preserving other appliance changes."""
from pathlib import Path
import shutil,sys,ast
root=Path(sys.argv[1]);src=Path(__file__).resolve().parents[1]/'appliance/dns'
app=root/'fastapi_app'
if not app.exists():app=root
def edit(path,old,new):
 p=app/path;s=p.read_text(encoding='utf-8')
 if new in s:return
 if old not in s:raise RuntimeError(f'Patch anchor missing: {path}')
 p.write_text(s.replace(old,new),encoding='utf-8')
shutil.copyfile(src/'dns_service.py',app/'api/dns_service.py')
shutil.copyfile(src/'dns_workspace.html',app/'templates/threats/dns_workspace.html')
shutil.copyfile(src/'dns_workspace_script.html',app/'templates/threats/dns_workspace_script.html')
shutil.copyfile(src/'dns_sources.html',app/'templates/devices/dns_sources.html')
edit('main.py','        path = request.url.path','        path = request.url.path\n        if path == "/api/dns/ingest":\n            return await call_next(request)  # DNS router enforces source-only authentication')
edit('core/csrf.py','    path = request.url.path','    path = request.url.path\n    if path == "/api/dns/ingest":\n        return True  # No cookie authentication; source credential required by the route')
edit('main.py','    # Run ClickHouse migrations','    from .api.dns_service import initialize as initialize_dns\n    await initialize_dns()\n\n    # Run ClickHouse migrations')
edit('main.py','app.include_router(threat_dashboard_router)','from .api.dns_service import router as dns_router\napp.include_router(dns_router)\napp.include_router(threat_dashboard_router)')
edit('api/threat_dashboard.py','    return _render("threats/url_dns_logs.html", request)','    return _render("threats/url_dns_logs.html" if request.query_params.get("tab") == "url" else "threats/dns_workspace.html", request)')
edit('templates/devices/device_list.html','<!-- Storage Dashboard -->',"{% include 'devices/dns_sources.html' %}\n<!-- Storage Dashboard -->")
edit('api/views.py', "            storage_stats = ClickHouseClient.get_storage_stats()\n            per_device_storage = ClickHouseClient.get_per_device_storage()\n            device_storage_map = {s['device_ip']: s for s in per_device_storage}", "            from .dns_service import device_storage_summary\n            from starlette.concurrency import run_in_threadpool\n            storage_stats, device_storage_map = await run_in_threadpool(device_storage_summary)")
edit('templates/devices/device_list.html','<th>Storage</th>','<th title="Estimated uncompressed storage for events in the last 24 hours">Storage (24h estimate)</th>')
edit('templates/devices/device_list.html','    location.reload();','    // Source health refreshes independently; do not discard an enrollment credential or active form.\n    if (!document.querySelector("#dns-sources details[open]") && !["INPUT","SELECT","TEXTAREA"].includes(document.activeElement.tagName)) location.reload();')
edit('models/device.py','    PALOALTO = "PALOALTO"','    PALOALTO = "PALOALTO"\n    WINDOWS_DNS = "WINDOWS_DNS"')
edit('models/device.py','        (PALOALTO, "Palo Alto"),','        (PALOALTO, "Palo Alto"),\n        (WINDOWS_DNS, "Windows DNS Server"),')
edit('templates/threats/url_dns_logs.html',"onclick=\"switchTab('dns')\"", "onclick=\"location.href='?tab=dns'\"")
for p in app.rglob('*.py'):ast.parse(p.read_text(encoding='utf-8'))
print('DNS application extension applied.')
