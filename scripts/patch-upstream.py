"""Apply narrowly scoped appliance changes to the pinned upstream source."""
from pathlib import Path
import sys
import ast

root = Path(sys.argv[1])
for p in root.rglob('*'):
    if p.is_file() and (p.suffix in {'.sh', '.py', '.yaml', '.yml', '.conf', '.ini'} or p.name == 'Dockerfile'):
        p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n'))

def replace(path, old, new):
    p = root / path
    s = p.read_text(encoding='utf-8')
    if old not in s:
        raise SystemExit(f'Expected upstream text missing: {path}: {old[:60]}')
    p.write_text(s.replace(old, new), encoding='utf-8')

replace('Dockerfile', 'node:20-alpine', 'node:22-alpine')
replace('Dockerfile', 'RUN pip install --no-cache-dir /tmp/wheels/*.whl', 'RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 && pip install --no-cache-dir /tmp/wheels/*.whl')
replace('fastapi_app/db/database.py', 'import logging', 'import logging\nimport os')
replace('fastapi_app/db/database.py', 'admin.set_password("changeme")', '''password = os.environ.get("ZENSHEILD_ADMIN_PASSWORD", "")
                if len(password) < 5 or len(password.encode()) > 72 or password == "changeme":
                    raise RuntimeError("ZenSheild requires a unique bootstrap admin password")
                admin.set_password(password)''')
replace('fastapi_app/db/database.py', 'Default admin user created (admin/changeme)', 'ZenSheild administrator created with deployment-specific credentials')
replace('fastapi_app/core/auth.py', 'PASSWORD_MIN_LENGTH = 8', 'PASSWORD_MIN_LENGTH = 5')
replace('fastapi_app/core/auth.py', 'at least 8 characters, with uppercase, lowercase, and a digit', 'at least 5 characters and at most 72 UTF-8 bytes')
replace('fastapi_app/core/auth.py', '''    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."''', '''    if len(password.encode()) > 72:
        return "Password must be at most 72 UTF-8 bytes."
    if any(c in password for c in '\\r\\n\\x00'):
        return "Password cannot contain line breaks or NUL."''')
replace('fastapi_app/api/setup.py', '''    # Validate current password is the default
    if current_password != "changeme":
        return JSONResponse({"error": "Current password is incorrect"}, status_code=400)
''', '')
replace('fastapi_app/api/setup.py', '        # Update password and email', '''        if not admin.verify_password(current_password):
            return JSONResponse({"error": "Current password is incorrect"}, status_code=400)

        # Update password and email''')
for path in ['fastapi_app/core/auth.py', 'fastapi_app/core/csrf.py']:
    replace(path, 'secure=False,', 'secure=True,')
replace('fastapi_app/core/csrf.py', 'csrf_token != csrf_cookie', 'not secrets.compare_digest(csrf_token, csrf_cookie)')
replace('fastapi_app/core/csrf.py', 'if request.headers.get("X-API-Key") or request.query_params.get("api_key"):', 'if getattr(request.state, "api_key", None) is not None:')
replace('fastapi_app/main.py', 'allow_origins=["*"] if settings.debug else settings.allowed_hosts_list,', 'allow_origins=[],  # Appliance UI is same-origin only')
replace('fastapi_app/api/devices.py', 'router = APIRouter(prefix="/devices", tags=["devices"])', '''from ..core.permissions import require_role

async def _authorize_device_operation(request: Request):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        roles = ("ADMIN", "ANALYST") if request.url.path.endswith(("/approve", "/reject")) else ("ADMIN",)
        await require_role(*roles)(request)

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(_authorize_device_operation)])''')
replace('fastapi_app/templates/setup/wizard.html', 'value="changeme"', 'value=""')
replace('fastapi_app/templates/auth/login.html', 'Zen<span>tryc</span>', 'Zen<span>Shield</span>')
replace('fastapi_app/templates/auth/login.html', 'SOAR / SIEM Platform', 'Security Appliance')
replace('fastapi_app/services/syslog_collector.py', "'status': DeviceStatus.APPROVED,", "'status': DeviceStatus.PENDING,")
replace('fastapi_app/services/syslog_collector.py', 'New device auto-approved:', 'New device awaiting approval:')
replace('fastapi_app/services/syslog_collector.py', 'return (DeviceStatus.APPROVED, detected_parser)', 'return (DeviceStatus.PENDING, detected_parser)')
replace('fastapi_app/services/syslog_collector.py', 'return (DeviceStatus.APPROVED, detected)', 'return None  # Fail closed if device authorization cannot be checked')
replace('fastapi_app/db/clickhouse.py', 'parsed_data Map(String, String) CODEC(ZSTD(1)),', "parsed_data Map(String, String) CODEC(ZSTD(1)),\n            log_time String DEFAULT '' CODEC(ZSTD(1)),")
replace('fastapi_app/db/clickhouse.py', '        migrations = [', '''        migrations = [
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_time String DEFAULT '' CODEC(ZSTD(1))",''')
replace('fastapi_app/db/clickhouse.py', '            client.command(create_table_query)\n            logger.info("ClickHouse table \'syslogs\' created/verified")', '''            client.command(create_table_query)
            client.command("ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_time String DEFAULT '' CODEC(ZSTD(1))")
            logger.info("ClickHouse table 'syslogs' created/verified")''')
# Product-facing text only; retain module, database and API identifiers.
for base in ['fastapi_app/templates', 'static']:
    for p in (root / base).rglob('*'):
        if p.suffix in {'.html', '.svg', '.js', '.css'}:
            s = p.read_text(encoding='utf-8')
            s = '\n'.join(line for line in s.split('\n') if 'fonts.googleapis.com' not in line and 'fonts.gstatic.com' not in line)
            p.write_text(s.replace('Zentryc', 'ZenSheild').replace('ZENTRYC', 'ZENSHEILD'), encoding='utf-8')
replace('fastapi_app/core/config.py', '"Zentryc SOAR/SIEM Platform"', '"ZenSheild SOAR/SIEM Appliance"')
# Starlette 1.x removed the deprecated name-first TemplateResponse form.
for p in (root / 'fastapi_app/api').glob('*.py'):
    s = p.read_text(encoding='utf-8')
    if 'templates.TemplateResponse(' in s:
        s = s.replace('templates.TemplateResponse(', 'templates.TemplateResponse(request, ')
        ast.parse(s)
        p.write_text(s, encoding='utf-8')
# Console-facing identifiers and generated web assets use the final product spelling.
for base in ['fastapi_app/templates', 'static']:
    for p in (root / base).rglob('*'):
        if p.suffix in {'.html', '.svg', '.js', '.css'}:
            p.write_text(p.read_text(encoding='utf-8').replace('ZenSheild', 'ZenShield').replace('ZENSHEILD', 'ZENSHIELD'), encoding='utf-8')
replace('fastapi_app/core/config.py', 'ZenSheild SOAR/SIEM Appliance', 'ZenShield SOAR/SIEM Appliance')
replace('fastapi_app/main.py', '"Zentryc SOAR/SIEM API"', '"ZenShield SOAR/SIEM API"')
replace('fastapi_app/api/views.py', '@router.get("/system/",', '@router.get("/system/storage-monitor/",')
replace('fastapi_app/api/views.py', 'name="system_monitor",', 'name="storage_monitor",')
replace('fastapi_app/templates/base.html', 'v{{ app_version }}', 'ZenShield 0.2.0')
# Revoke sessions reliably when Redis is unavailable instead of accepting stale JWTs.
replace('fastapi_app/core/auth.py', 'return jti in _revoked_tokens_fallback', 'return True  # Authentication fails closed while the session store is unavailable')
import shutil
control = Path(__file__).resolve().parent.parent / 'appliance' / 'control'
shutil.copyfile(control / 'api.py', root / 'fastapi_app/api/appliance.py')
shutil.copyfile(control / 'system.html', root / 'fastapi_app/templates/system/appliance.html')
shutil.copyfile(control / 'reset_password.py', root / 'zenshield_reset_password.py')
with (root / 'Dockerfile').open('a') as f:
    f.write('\nCOPY zenshield_reset_password.py /app/zenshield_reset_password.py\n')
with (root / 'fastapi_app/api/views.py').open('a') as f:
    f.write('''\n@router.get("/system/", response_class=HTMLResponse, name="system_monitor", dependencies=[Depends(require_role("ADMIN"))])
async def appliance_management(request: Request):
    return _render("system/appliance.html", request, {})
''')
with (root / 'fastapi_app/main.py').open('a') as f:
    f.write('\nfrom .api.appliance import router as appliance_router\napp.include_router(appliance_router)\n')
print('Applied ZenShield branding, appliance management and authentication hardening')
# Keep native/future image builds aligned with the DNS feature deployed on the appliance.
import subprocess
subprocess.run([sys.executable,str(Path(__file__).with_name('patch-dns.py')),str(root)],check=True)
subprocess.run([sys.executable,str(Path(__file__).with_name('patch-storage.py')),str(root)],check=True)
dns_distribution=Path(__file__).resolve().parents[1]/'appliance/dns-agent-release'
if dns_distribution.exists():
    shutil.copytree(dns_distribution,root/'dns-agent',dirs_exist_ok=True)
    with (root/'Dockerfile').open('a') as f:f.write('\nCOPY dns-agent /app/dns-agent\n')
