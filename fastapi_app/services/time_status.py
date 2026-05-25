"""
Read-only system time status.

Surfaces the host's clock, timezone, and NTP synchronization state to the
admin UI. Everything here is read-only: in the Docker appliance the host
controls its own clock, and writing time settings from inside the container
requires CAP_SYS_TIME or a host-shell escape we deliberately do not give the
web process. The admin UI links to the appliance setup guide instead.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)


def _read_etc_timezone() -> Optional[str]:
    """Read /etc/timezone if present (Debian/Ubuntu)."""
    try:
        with open("/etc/timezone") as f:
            v = f.read().strip()
            return v or None
    except OSError:
        return None


def _read_localtime_link() -> Optional[str]:
    """Read the symlink target of /etc/localtime → /usr/share/zoneinfo/X."""
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        return None
    # Typical form: /usr/share/zoneinfo/Asia/Riyadh
    marker = "zoneinfo/"
    idx = target.rfind(marker)
    if idx >= 0:
        return target[idx + len(marker):]
    return None


def _detect_system_timezone() -> str:
    """Best-effort detection of the host's IANA timezone name."""
    for getter in (_read_etc_timezone, _read_localtime_link):
        try:
            v = getter()
            if v:
                ZoneInfo(v)  # validate
                return v
        except (ZoneInfoNotFoundError, ValueError, OSError):
            continue
    # Fall back to the Python tzname; not guaranteed to be IANA.
    try:
        return datetime.now().astimezone().tzname() or "UTC"
    except Exception:
        return "UTC"


def _timedatectl_status() -> dict:
    """Parse ``timedatectl show`` key=value output. Returns empty dict if
    timedatectl is not available (e.g. inside a slim container)."""
    if shutil.which("timedatectl") is None:
        return {}
    try:
        out = subprocess.run(
            ["timedatectl", "show"],
            capture_output=True, text=True, timeout=2,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug(f"timedatectl unavailable: {e}")
        return {}
    if out.returncode != 0:
        return {}
    data = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            data[k.strip()] = v.strip()
    return data


def _chronyc_sources() -> list:
    """Optional: chrony peer state if chronyc is installed. Each entry is
    ``{"address": str, "stratum": int, "state": str}`` (state ≈ ``^*`` master)."""
    if shutil.which("chronyc") is None:
        return []
    try:
        out = subprocess.run(
            ["chronyc", "-c", "sources"],
            capture_output=True, text=True, timeout=2,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if out.returncode != 0:
        return []
    peers = []
    for line in out.stdout.splitlines():
        parts = line.split(",")
        if len(parts) >= 4:
            peers.append({
                "address": parts[2],
                "stratum": parts[3],
                "state": parts[1],
            })
    return peers


def get_time_status() -> dict:
    """Snapshot of current time / TZ / NTP state.

    ``synchronized``, ``ntp_service``, ``ntp_active`` come from
    ``timedatectl show`` when available. ``ntp_peers`` (if any) comes from
    chrony. Everything is best-effort: a missing tool yields a missing field
    rather than an exception."""
    now_utc = datetime.now(timezone.utc)
    system_tz = _detect_system_timezone()
    try:
        local_now = now_utc.astimezone(ZoneInfo(system_tz))
    except (ZoneInfoNotFoundError, ValueError, OSError):
        local_now = now_utc

    td = _timedatectl_status()

    def _bool(v: Optional[str]) -> Optional[bool]:
        if v is None:
            return None
        return v.lower() == "yes"

    return {
        "now_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "now_local": local_now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "system_timezone": system_tz,
        "td_timezone": td.get("Timezone"),
        "synchronized": _bool(td.get("NTPSynchronized")),
        "ntp_active": _bool(td.get("NTP")),
        "ntp_service_can_be_enabled": _bool(td.get("CanNTP")),
        "rtc_in_local_tz": _bool(td.get("LocalRTC")),
        "ntp_peers": _chronyc_sources(),
        "in_container": os.path.exists("/.dockerenv"),
    }
