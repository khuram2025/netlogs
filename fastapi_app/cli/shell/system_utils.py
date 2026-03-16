"""Privileged command wrappers — all sudo subprocess calls go through here."""

import subprocess
import os

DEFAULT_TIMEOUT = 30
ZENTRYC_DIR = os.environ.get("ZENTRYC_DIR", "/opt/zentryc")
ENV_FILE = os.path.join(ZENTRYC_DIR, ".env")
BACKUP_SCRIPT = os.path.join(ZENTRYC_DIR, "scripts", "backup.sh")
UPGRADE_SCRIPT = "/usr/local/bin/zentryc-upgrade"


class CommandError(Exception):
    """Raised when a system command fails."""
    def __init__(self, message: str, returncode: int = 1):
        self.message = message
        self.returncode = returncode
        super().__init__(message)


def run_cmd(args: list[str], timeout: int = DEFAULT_TIMEOUT, capture: bool = True) -> str:
    """Run a command and return stdout. Raises CommandError on failure."""
    try:
        result = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            err = result.stderr.strip() if result.stderr else f"Command exited with code {result.returncode}"
            raise CommandError(err, result.returncode)
        return result.stdout.strip() if result.stdout else ""
    except subprocess.TimeoutExpired:
        raise CommandError(f"Command timed out after {timeout}s")
    except FileNotFoundError:
        raise CommandError(f"Command not found: {args[0]}")


def sudo_run(args: list[str], timeout: int = DEFAULT_TIMEOUT, capture: bool = True) -> str:
    """Run a command via sudo."""
    return run_cmd(["sudo"] + args, timeout=timeout, capture=capture)


def sudo_tee(path: str, content: str) -> None:
    """Write content to a file via sudo tee."""
    try:
        proc = subprocess.run(
            ["sudo", "/usr/bin/tee", path],
            input=content,
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )
        if proc.returncode != 0:
            raise CommandError(f"Failed to write {path}: {proc.stderr.strip()}")
    except subprocess.TimeoutExpired:
        raise CommandError(f"Timed out writing {path}")


# ── Service management ──────────────────────────────────────────────

SERVICE_MAP = {
    "web": "zentryc-web",
    "syslog": "zentryc-syslog",
    "nginx": "nginx",
}


def restart_service(name: str) -> str:
    """Restart a systemd service."""
    unit = SERVICE_MAP.get(name, name)
    return sudo_run(["/usr/bin/systemctl", "restart", unit])


def get_service_status(unit: str) -> dict:
    """Get service active state and sub-state."""
    try:
        active = run_cmd(
            ["systemctl", "is-active", unit], timeout=5
        )
    except CommandError:
        active = "inactive"
    try:
        output = run_cmd(
            ["systemctl", "show", unit, "--property=SubState,MainPID,ActiveEnterTimestamp"],
            timeout=5,
        )
        props = {}
        for line in output.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k] = v
        return {
            "active": active,
            "sub": props.get("SubState", "unknown"),
            "pid": props.get("MainPID", ""),
            "since": props.get("ActiveEnterTimestamp", ""),
        }
    except CommandError:
        return {"active": active, "sub": "unknown", "pid": "", "since": ""}


# ── System info ─────────────────────────────────────────────────────

def get_hostname() -> str:
    return run_cmd(["hostname"], timeout=5)


def get_uptime_seconds() -> int:
    raw = run_cmd(["cat", "/proc/uptime"], timeout=5)
    return int(float(raw.split()[0]))


def get_cpu_usage() -> float:
    """Get CPU usage percentage from /proc/stat (1-second sample)."""
    import time

    def read_stat():
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        idle = int(parts[4])
        total = sum(int(x) for x in parts[1:])
        return idle, total

    idle1, total1 = read_stat()
    time.sleep(0.5)
    idle2, total2 = read_stat()

    idle_delta = idle2 - idle1
    total_delta = total2 - total1
    if total_delta == 0:
        return 0.0
    return (1.0 - idle_delta / total_delta) * 100.0


def get_memory_info() -> dict:
    """Get memory stats from /proc/meminfo."""
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(":")
                info[key] = int(parts[1]) * 1024  # Convert kB to bytes
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", 0)
    used = total - available
    return {"total": total, "used": used, "available": available}


def get_disk_info(path: str = "/") -> dict:
    """Get disk usage for a path."""
    st = os.statvfs(path)
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = total - free
    return {"total": total, "used": used, "free": free}


def get_interfaces() -> str:
    """Get network interface summary."""
    return run_cmd(["ip", "-br", "addr", "show"], timeout=5)


# ── Privileged system commands ──────────────────────────────────────

def set_hostname(name: str) -> str:
    return sudo_run(["/usr/bin/hostnamectl", "set-hostname", name])


def set_timezone(tz: str) -> str:
    return sudo_run(["/usr/bin/timedatectl", "set-timezone", tz])


def apply_netplan() -> str:
    return sudo_run(["/usr/sbin/netplan", "apply"], timeout=60)


def system_reboot() -> str:
    return sudo_run(["/usr/bin/systemctl", "reboot"])


def system_poweroff() -> str:
    return sudo_run(["/usr/bin/systemctl", "poweroff"])


def run_backup() -> str:
    """Run the backup script."""
    return sudo_run([BACKUP_SCRIPT], timeout=600)


def run_upgrade(path: str) -> str:
    """Run the upgrade script with a tarball path."""
    return sudo_run([UPGRADE_SCRIPT, path], timeout=600, capture=False)


def write_timesyncd_conf(ntp_server: str) -> None:
    """Write NTP configuration."""
    content = f"[Time]\nNTP={ntp_server}\nFallbackNTP=ntp.ubuntu.com\n"
    sudo_tee("/etc/systemd/timesyncd.conf", content)
    sudo_run(["/usr/bin/systemctl", "restart", "systemd-timesyncd"])


def read_env_file() -> dict:
    """Read the .env file into a dict."""
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


def get_version() -> str:
    """Read the application version."""
    version_file = os.path.join(ZENTRYC_DIR, "fastapi_app", "__version__.py")
    try:
        with open(version_file) as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    # Fallback: try relative import
    try:
        from fastapi_app.__version__ import __version__
        return __version__
    except ImportError:
        return "unknown"
