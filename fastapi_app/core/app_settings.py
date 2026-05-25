"""
App-wide display settings.

Currently this module owns the **display timezone** — the timezone the UI
renders timestamps in. All data is stored and queried in UTC; this setting
only affects presentation.

It is one global setting (key ``display_timezone`` in ``system_settings``).
Because the value is read by a *synchronous* Jinja filter on every rendered
timestamp, it is cached in-process. To stay correct across uvicorn workers
the value is also mirrored to a small file that every worker re-reads on a
short TTL — so a change made in the UI propagates without a restart.
"""

import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from sqlalchemy import select

from ..db.database import async_session_maker
from ..models.system_settings import SystemSetting

logger = logging.getLogger(__name__)

DISPLAY_TZ_KEY = "display_timezone"
SOURCE_TZ_KEY = "default_source_tz"
DEFAULT_TIMEZONE = "UTC"

# Cross-worker cache mirror. The DB is the persistent source of truth; this
# file lets the other workers see a change made by the worker that handled
# the save, without waiting for a restart.
_TZ_FILE = os.path.join(tempfile.gettempdir(), "zentryc_display_tz")
_SRC_TZ_FILE = os.path.join(tempfile.gettempdir(), "zentryc_source_tz")
_CACHE_TTL = 5.0  # seconds

_cache_val = DEFAULT_TIMEZONE
_cache_at = 0.0

# Default source-device timezone — used by the syslog collector when parsing
# device-local timestamps that lack an offset and the device itself has no
# per-device TZ override set. The syslog hot path hits this on every record
# so the lookup must be lock-free and cheap (file mirror, no DB).
_src_cache_val = DEFAULT_TIMEZONE
_src_cache_at = 0.0


def all_timezones() -> list:
    """Sorted IANA timezone names for the settings dropdown, UTC first."""
    return ["UTC"] + sorted(z for z in available_timezones() if z != "UTC")


def is_valid_timezone(name) -> bool:
    """True if ``name`` is a usable IANA timezone."""
    if not name:
        return False
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return False


def _write_mirror(tz: str) -> None:
    try:
        with open(_TZ_FILE, "w") as f:
            f.write(tz)
    except OSError as e:
        logger.warning(f"Could not write display-tz mirror file: {e}")


def _write_src_mirror(tz: str) -> None:
    try:
        with open(_SRC_TZ_FILE, "w") as f:
            f.write(tz)
    except OSError as e:
        logger.warning(f"Could not write source-tz mirror file: {e}")


def get_display_timezone() -> str:
    """Current display timezone (IANA name). Synchronous and cheap — safe to
    call from a Jinja filter. Re-reads the cross-worker mirror at most once
    per ``_CACHE_TTL`` seconds."""
    global _cache_val, _cache_at
    now = time.monotonic()
    if now - _cache_at < _CACHE_TTL:
        return _cache_val
    _cache_at = now
    try:
        with open(_TZ_FILE) as f:
            val = f.read().strip()
        if is_valid_timezone(val):
            _cache_val = val
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.debug(f"display-tz mirror read failed: {e}")
    return _cache_val


async def load_display_timezone() -> str:
    """Load the persisted setting from the DB into the cache + mirror.
    Called once at startup."""
    global _cache_val, _cache_at
    tz = DEFAULT_TIMEZONE
    try:
        async with async_session_maker() as db:
            row = (await db.execute(
                select(SystemSetting).where(
                    SystemSetting.key == DISPLAY_TZ_KEY)
            )).scalar_one_or_none()
        if row and is_valid_timezone(row.value):
            tz = row.value
    except Exception as e:
        logger.warning(f"Could not load display timezone: {e}")
    _cache_val = tz
    _cache_at = time.monotonic()
    _write_mirror(tz)
    return tz


def get_default_source_timezone() -> str:
    """Current default source-device timezone (IANA name). Cheap and
    synchronous — called on the syslog hot path."""
    global _src_cache_val, _src_cache_at
    now = time.monotonic()
    if now - _src_cache_at < _CACHE_TTL:
        return _src_cache_val
    _src_cache_at = now
    try:
        with open(_SRC_TZ_FILE) as f:
            val = f.read().strip()
        if is_valid_timezone(val):
            _src_cache_val = val
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.debug(f"source-tz mirror read failed: {e}")
    return _src_cache_val


async def load_default_source_timezone() -> str:
    """Load the persisted default-source-tz from the DB at startup. On a
    fresh install (no row yet) we seed it from the ``ZENTRYC_DEFAULT_SOURCE_TZ``
    env var if set, otherwise leave it at UTC — the admin must pick one
    explicitly to opt into event-time parsing for naive device timestamps."""
    global _src_cache_val, _src_cache_at
    tz = DEFAULT_TIMEZONE
    try:
        async with async_session_maker() as db:
            row = (await db.execute(
                select(SystemSetting).where(
                    SystemSetting.key == SOURCE_TZ_KEY)
            )).scalar_one_or_none()
            if row and is_valid_timezone(row.value):
                tz = row.value
            elif row is None:
                seed = os.environ.get("ZENTRYC_DEFAULT_SOURCE_TZ", "").strip()
                if seed and is_valid_timezone(seed):
                    tz = seed
                    db.add(SystemSetting(key=SOURCE_TZ_KEY, value=tz))
                    await db.commit()
                    logger.info(f"Seeded default source timezone: {tz}")
    except Exception as e:
        logger.warning(f"Could not load default source timezone: {e}")
    _src_cache_val = tz
    _src_cache_at = time.monotonic()
    _write_src_mirror(tz)
    return tz


async def set_default_source_timezone(db, name: str) -> str:
    """Validate and persist the default source-device timezone."""
    global _src_cache_val, _src_cache_at
    if not is_valid_timezone(name):
        raise ValueError(f"Unknown timezone: {name!r}")
    row = (await db.execute(
        select(SystemSetting).where(SystemSetting.key == SOURCE_TZ_KEY)
    )).scalar_one_or_none()
    if row:
        row.value = name
    else:
        db.add(SystemSetting(key=SOURCE_TZ_KEY, value=name))
    await db.commit()
    _src_cache_val = name
    _src_cache_at = time.monotonic()
    _write_src_mirror(name)
    return name


async def set_display_timezone(db, name: str) -> str:
    """Validate and persist a new display timezone. Updates the DB (source of
    truth), the in-process cache, and the cross-worker mirror file."""
    global _cache_val, _cache_at
    if not is_valid_timezone(name):
        raise ValueError(f"Unknown timezone: {name!r}")
    row = (await db.execute(
        select(SystemSetting).where(SystemSetting.key == DISPLAY_TZ_KEY)
    )).scalar_one_or_none()
    if row:
        row.value = name
    else:
        db.add(SystemSetting(key=DISPLAY_TZ_KEY, value=name))
    await db.commit()
    _cache_val = name
    _cache_at = time.monotonic()
    _write_mirror(name)
    return name


def to_display_tz(value):
    """Coerce a datetime or ISO-ish string to a tz-aware datetime in the
    display timezone. Naive inputs are treated as UTC (the storage contract).
    Returns None if the value cannot be parsed."""
    if value is None or value == "":
        return None
    dt = value
    if not isinstance(dt, datetime):
        s = str(value).strip().replace("T", " ")
        # Drop any trailing zone marker — stored values are UTC by contract.
        for marker in ("Z", "z", "+"):
            idx = s.find(marker, 10)
            if idx > 0:
                s = s[:idx]
        s = s.strip()
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.astimezone(ZoneInfo(get_display_timezone()))
    except Exception:
        return dt.astimezone(timezone.utc)


def format_datetime(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Jinja filter ``localdt``: render a datetime / ISO string in the app's
    display timezone. Empty input renders as an empty string; an unparseable
    value is returned unchanged."""
    dt = to_display_tz(value)
    if dt is None:
        return "" if value in (None, "") else str(value)
    return dt.strftime(fmt)
