"""show commands — system status, health, interfaces, services, version, disk, logs, config."""

import json
import urllib.request
import urllib.error

from ..formatters import (
    print_table, print_kv, print_section, bold, success, warning, error, info,
    format_bytes, format_uptime, format_percent, status_color,
)
from ..system_utils import (
    get_hostname, get_uptime_seconds, get_cpu_usage, get_memory_info,
    get_disk_info, get_interfaces, get_service_status, get_version,
    read_env_file, run_cmd, CommandError,
)


SERVICES = [
    ("zentryc-web", "Web Application"),
    ("zentryc-syslog", "Syslog Collector"),
    ("nginx", "Nginx Reverse Proxy"),
    ("postgresql", "PostgreSQL Database"),
    ("clickhouse-server", "ClickHouse Database"),
]

HEALTH_URL = "http://127.0.0.1:8000/api/health"

# Keys that contain sensitive values
MASKED_KEYS = {"PASSWORD", "SECRET", "KEY", "TOKEN"}


def cmd_show(args: list[str]) -> None:
    """Dispatch show subcommands."""
    if not args:
        print(error("Usage: show <system status|system health|interfaces|services|version|disk usage|logs count|running-config>"))
        return

    sub = args[0].lower()

    if sub == "system" and len(args) > 1:
        sub2 = args[1].lower()
        if sub2 == "status":
            _show_system_status()
        elif sub2 == "health":
            _show_system_health()
        else:
            print(error(f"Unknown: show system {sub2}"))
    elif sub == "interfaces":
        _show_interfaces()
    elif sub == "services":
        _show_services()
    elif sub == "version":
        _show_version()
    elif sub == "disk":
        if len(args) > 1 and args[1].lower() == "usage":
            _show_disk_usage()
        else:
            print(error("Usage: show disk usage"))
    elif sub == "logs":
        if len(args) > 1 and args[1].lower() == "count":
            period = args[2].lower() if len(args) > 2 else "all"
            _show_logs_count(period)
        else:
            print(error("Usage: show logs count [today|week|month|all]"))
    elif sub == "running-config":
        _show_running_config()
    else:
        print(error(f"Unknown: show {sub}"))


def _show_system_status() -> None:
    """Show system status overview."""
    print_section("System Status")

    version = get_version()
    hostname = get_hostname()
    uptime = format_uptime(get_uptime_seconds())
    cpu = get_cpu_usage()
    mem = get_memory_info()
    disk = get_disk_info("/")

    mem_pct = (mem["used"] / mem["total"] * 100) if mem["total"] else 0
    disk_pct = (disk["used"] / disk["total"] * 100) if disk["total"] else 0

    print_kv([
        ("Hostname", hostname),
        ("Version", info(version)),
        ("Uptime", uptime),
        ("CPU Usage", format_percent(cpu)),
        ("Memory", f"{format_bytes(mem['used'])} / {format_bytes(mem['total'])} ({format_percent(mem_pct)})"),
        ("Disk", f"{format_bytes(disk['used'])} / {format_bytes(disk['total'])} ({format_percent(disk_pct)})"),
    ])

    # Quick service check
    print_section("Services")
    rows = []
    for unit, label in SERVICES:
        st = get_service_status(unit)
        rows.append([label, status_color(st["active"]), st.get("pid", "")])
    print_table(["Service", "Status", "PID"], rows)


def _show_system_health() -> None:
    """Show health from the web API endpoint."""
    print_section("System Health")
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(error(f"  Cannot reach health endpoint: {e.reason}"))
        return
    except Exception as e:
        print(error(f"  Health check failed: {e}"))
        return

    overall = data.get("status", "unknown")
    print_kv([
        ("Overall", status_color(overall.upper())),
        ("Version", data.get("version", "?")),
        ("Uptime", format_uptime(data.get("uptime_seconds", 0))),
    ])

    components = data.get("components", {})
    if components:
        print_section("Components")
        rows = []
        for name, comp in components.items():
            st = comp.get("status", "unknown")
            detail = ""
            if "latency_ms" in comp:
                detail = f"{comp['latency_ms']:.0f}ms"
            elif "total_rows" in comp:
                detail = f"{comp['total_rows']} rows"
            elif "eps" in comp:
                detail = f"{comp['eps']:.1f} eps"
            elif "jobs" in comp:
                detail = f"{comp['jobs']} jobs"
            rows.append([name, status_color(st), detail])
        print_table(["Component", "Status", "Detail"], rows)


def _show_interfaces() -> None:
    """Show network interfaces."""
    print_section("Network Interfaces")
    try:
        output = get_interfaces()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                state = parts[1]
                addrs = " ".join(parts[2:])
                state_colored = success(state) if state == "UP" else error(state)
                print(f"  {bold(name):<25} {state_colored:<20} {addrs}")
            else:
                print(f"  {line}")
    except CommandError as e:
        print(error(f"  Failed: {e.message}"))


def _show_services() -> None:
    """Show all service statuses."""
    print_section("Service Status")
    rows = []
    for unit, label in SERVICES:
        st = get_service_status(unit)
        rows.append([
            label,
            unit,
            status_color(st["active"]),
            st.get("sub", ""),
            st.get("pid", ""),
            st.get("since", "")[:19] if st.get("since") else "",
        ])
    print_table(["Service", "Unit", "Status", "Sub-State", "PID", "Since"], rows)


def _show_version() -> None:
    """Show application version."""
    version = get_version()
    print(f"\n  Zentryc SOAR/SIEM Platform {info('v' + version)}")


def _show_disk_usage() -> None:
    """Show disk usage summary."""
    print_section("Disk Usage")

    # Filesystem usage
    for mount in ["/", "/opt/zentryc", "/var/lib/postgresql", "/var/lib/clickhouse"]:
        try:
            d = get_disk_info(mount)
            pct = (d["used"] / d["total"] * 100) if d["total"] else 0
            print(f"  {bold(mount):<30} {format_bytes(d['used']):>10} / {format_bytes(d['total']):>10}  {format_percent(pct)}")
        except OSError:
            pass

    # ClickHouse table sizes
    print_section("ClickHouse Tables")
    try:
        output = _clickhouse_query(
            "SELECT database, table, formatReadableSize(sum(bytes_on_disk)) as size, "
            "sum(rows) as rows FROM system.parts WHERE active "
            "GROUP BY database, table ORDER BY sum(bytes_on_disk) DESC"
        )
        if output:
            rows = []
            for line in output.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    rows.append(parts)
            if rows:
                print_table(["Database", "Table", "Size", "Rows"], rows)
        else:
            print("  No ClickHouse data found")
    except Exception:
        print("  Could not query ClickHouse table sizes")


def _show_logs_count(period: str) -> None:
    """Show log counts by period."""
    print_section("Log Counts")

    where = ""
    if period == "today":
        where = "WHERE timestamp >= today()"
    elif period == "week":
        where = "WHERE timestamp >= today() - 7"
    elif period == "month":
        where = "WHERE timestamp >= today() - 30"
    elif period != "all":
        print(error(f"  Unknown period: {period}. Use: today, week, month, all"))
        return

    try:
        count = _clickhouse_query(f"SELECT count() FROM zentryc.syslogs {where}")
        print(f"  Period: {bold(period)}")
        print(f"  Total logs: {info(count.strip() if count else '0')}")
    except Exception as e:
        print(error(f"  Failed to query logs: {e}"))


def _show_running_config() -> None:
    """Show current .env configuration with masked passwords."""
    print_section("Running Configuration")
    env = read_env_file()
    if not env:
        print("  No configuration file found")
        return

    for key, value in env.items():
        if any(s in key.upper() for s in MASKED_KEYS):
            display = "********"
        else:
            display = value
        print(f"  {bold(key):<40} {display}")


def _clickhouse_query(query: str) -> str:
    """Run a ClickHouse query via HTTP interface."""
    env = read_env_file()
    ch_host = env.get("CLICKHOUSE_HOST", "127.0.0.1")
    ch_port = env.get("CLICKHOUSE_HTTP_PORT", env.get("CLICKHOUSE_PORT", "8123"))
    ch_user = env.get("CLICKHOUSE_USER", "default")
    ch_pass = env.get("CLICKHOUSE_PASSWORD", "")

    url = f"http://{ch_host}:{ch_port}/"
    data = query.encode()

    req = urllib.request.Request(url, data=data, method="POST")
    if ch_user:
        import base64
        creds = base64.b64encode(f"{ch_user}:{ch_pass}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")

    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode()
