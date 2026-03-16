"""Config appliers for the first-boot wizard.

Applies the configuration gathered from wizard screens:
netplan, hostname, timezone, database setup, .env generation, admin user.
"""

import os
import secrets
import subprocess
import time

INSTALL_DIR = os.environ.get("ZENTRYC_DIR", "/opt/zentryc")
ENV_FILE = os.path.join(INSTALL_DIR, ".env")
CONFIGURED_MARKER = os.path.join(INSTALL_DIR, ".configured")
NETPLAN_FILE = "/etc/netplan/01-zentryc.yaml"


def _run(args: list[str], timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command with timeout."""
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=check,
    )


def _sudo(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return _run(["sudo"] + args, timeout=timeout)


def _generate_password() -> str:
    """Generate a secure random password."""
    return secrets.token_urlsafe(24)


def apply_network(config: dict, log_fn=None) -> None:
    """Apply network configuration via netplan.

    config keys: mode (static/dhcp), interface, address, gateway, dns1, dns2
    """
    log = log_fn or print
    iface = config.get("interface", "eth0")
    mode = config.get("mode", "dhcp")

    if mode == "dhcp":
        yaml_content = f"""network:
  version: 2
  ethernets:
    {iface}:
      dhcp4: true
"""
    else:
        yaml_content = f"""network:
  version: 2
  ethernets:
    {iface}:
      dhcp4: false
      addresses:
        - {config['address']}
"""
        if config.get("gateway"):
            yaml_content += f"""      routes:
        - to: default
          via: {config['gateway']}
"""
        dns_servers = []
        if config.get("dns1"):
            dns_servers.append(config["dns1"])
        if config.get("dns2"):
            dns_servers.append(config["dns2"])
        if dns_servers:
            servers = ", ".join(dns_servers)
            yaml_content += f"""      nameservers:
        addresses: [{servers}]
"""

    # Write netplan config
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", NETPLAN_FILE],
        input=yaml_content, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write netplan: {proc.stderr}")

    log("  Applying network configuration...")
    _sudo(["/usr/sbin/netplan", "apply"], timeout=60)
    log("  Network configured.")


def apply_system(config: dict, log_fn=None) -> None:
    """Apply system settings: hostname, timezone, NTP.

    config keys: hostname, timezone, ntp_server
    """
    log = log_fn or print

    if config.get("hostname"):
        _sudo(["/usr/bin/hostnamectl", "set-hostname", config["hostname"]])
        log(f"  Hostname set to: {config['hostname']}")

    if config.get("timezone"):
        _sudo(["/usr/bin/timedatectl", "set-timezone", config["timezone"]])
        log(f"  Timezone set to: {config['timezone']}")

    if config.get("ntp_server"):
        ntp_conf = f"[Time]\nNTP={config['ntp_server']}\nFallbackNTP=ntp.ubuntu.com\n"
        subprocess.run(
            ["sudo", "/usr/bin/tee", "/etc/systemd/timesyncd.conf"],
            input=ntp_conf, capture_output=True, text=True, timeout=10,
        )
        _sudo(["/usr/bin/systemctl", "restart", "systemd-timesyncd"])
        log(f"  NTP configured: {config['ntp_server']}")


def apply_database(log_fn=None) -> tuple[str, str]:
    """Configure PostgreSQL and ClickHouse with random passwords.

    Returns (pg_password, ch_password).
    """
    log = log_fn or print
    pg_pass = _generate_password()
    ch_pass = _generate_password()

    # PostgreSQL setup
    log("  Configuring PostgreSQL...")
    try:
        # Create user and database
        _run([
            "sudo", "-u", "postgres", "psql", "-c",
            f"DO $$ BEGIN "
            f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zentryc') THEN "
            f"CREATE USER zentryc WITH PASSWORD '{pg_pass}'; "
            f"END IF; END $$;",
        ])
        _run([
            "sudo", "-u", "postgres", "psql", "-c",
            "SELECT 1 FROM pg_database WHERE datname = 'zentryc'",
        ])
        # Try create DB (ignore if exists)
        _run([
            "sudo", "-u", "postgres", "psql", "-c",
            f"CREATE DATABASE zentryc OWNER zentryc;",
        ], check=False)
        _run([
            "sudo", "-u", "postgres", "psql", "-c",
            f"ALTER USER zentryc WITH PASSWORD '{pg_pass}';",
        ])
        _run([
            "sudo", "-u", "postgres", "psql", "-c",
            "GRANT ALL PRIVILEGES ON DATABASE zentryc TO zentryc;",
        ])
        log("  PostgreSQL user and database configured.")
    except Exception as e:
        log(f"  WARNING: PostgreSQL setup error: {e}")

    # ClickHouse setup
    log("  Configuring ClickHouse...")
    try:
        _run([
            "clickhouse-client", "--query",
            f"CREATE USER IF NOT EXISTS zentryc IDENTIFIED WITH sha256_password BY '{ch_pass}';",
        ], check=False)
        _run([
            "clickhouse-client", "--query",
            "GRANT ALL ON default.* TO zentryc;",
        ], check=False)
        log("  ClickHouse user configured.")
    except Exception as e:
        log(f"  WARNING: ClickHouse setup error: {e}")

    return pg_pass, ch_pass


def apply_env(pg_pass: str, ch_pass: str, config: dict, log_fn=None) -> None:
    """Generate the .env configuration file.

    config keys: hostname (optional)
    """
    log = log_fn or print
    secret_key = secrets.token_urlsafe(32) + secrets.token_urlsafe(32)

    env_content = f"""# =============================================================================
# Zentryc SOAR/SIEM Platform - Production Configuration
# Generated by first-boot wizard on {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
# =============================================================================

# --- Application ---
DEBUG=false
SECRET_KEY={secret_key}
ALLOWED_HOSTS=*
TZ={config.get('timezone', 'UTC')}

# --- PostgreSQL ---
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=zentryc
POSTGRES_USER=zentryc
POSTGRES_PASSWORD={pg_pass}

# --- ClickHouse ---
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_DB=default
CLICKHOUSE_USER=zentryc
CLICKHOUSE_PASSWORD={ch_pass}

# --- Web Server ---
WORKERS=4

# --- Syslog Collector ---
SYSLOG_PORT=514
SYSLOG_BATCH_SIZE=5000
SYSLOG_FLUSH_INTERVAL=2.0
SYSLOG_CACHE_TTL=60
SYSLOG_WORKERS=4
SYSLOG_MAX_BUFFER=100000
SYSLOG_METRICS_INTERVAL=30

# --- Logging ---
LOG_LEVEL=INFO
LOG_FILE=logs/zentryc.log
"""

    # Write via sudo (owned by zentryc user)
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", ENV_FILE],
        input=env_content, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write .env: {proc.stderr}")

    _sudo(["chmod", "600", ENV_FILE])
    _sudo(["chown", "zentryc:zentryc", ENV_FILE])
    log("  Configuration file generated.")


def start_services_and_create_admin(admin_password: str, admin_email: str = "", log_fn=None) -> None:
    """Start services, wait for health, create admin user.

    Args:
        admin_password: The admin password set in the wizard
        admin_email: Optional admin email
    """
    log = log_fn or print

    # Start web service
    log("  Starting web service...")
    _sudo(["/usr/bin/systemctl", "start", "zentryc-web"])

    # Wait for health
    log("  Waiting for web service to become healthy...")
    healthy = False
    for i in range(30):
        try:
            result = _run(
                ["curl", "-sf", "http://127.0.0.1:8000/api/health/simple"],
                timeout=5, check=False,
            )
            if result.returncode == 0:
                healthy = True
                break
        except Exception:
            pass
        time.sleep(2)

    if not healthy:
        log("  WARNING: Web service health check timed out")
        log("  Attempting to create admin user anyway...")

    # Create admin user via the setup API or direct DB
    log("  Creating admin user...")
    try:
        import json
        import urllib.request

        payload = json.dumps({
            "username": "admin",
            "password": admin_password,
            "email": admin_email or None,
            "role": "ADMIN",
        }).encode()

        req = urllib.request.Request(
            "http://127.0.0.1:8000/auth/setup/step1",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                log("  Admin user created via setup API.")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                log("  Admin user already exists (setup already completed).")
            else:
                raise
    except Exception as e:
        log(f"  WARNING: Could not create admin via API: {e}")
        log("  You may need to create admin user manually after login.")

    # Start syslog service
    log("  Starting syslog collector...")
    _sudo(["/usr/bin/systemctl", "start", "zentryc-syslog"])

    # Start disk cleanup timer
    _sudo(["/usr/bin/systemctl", "start", "zentryc-disk-cleanup.timer"], timeout=10)

    log("  All services started.")


def write_configured_marker(log_fn=None) -> None:
    """Write the .configured marker to prevent wizard from running again."""
    log = log_fn or print
    marker_content = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", CONFIGURED_MARKER],
        input=marker_content, capture_output=True, text=True, timeout=10,
    )
    _sudo(["chown", "zentryc:zentryc", CONFIGURED_MARKER])
    log("  Configuration marker written.")
