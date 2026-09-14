"""
Event-time parsing for ingested syslog records.

Stores the *event time* the device reports as the primary ``timestamp`` for
each row in ClickHouse, and the collector-receive moment as ``ingest_time``.
This is the SIEM industry convention (Splunk ``_time``, Elastic ``@timestamp``,
Graylog, QRadar) — users want to see when the event actually happened, with
ingest time available as a secondary field to surface pipeline lag.

Devices typically emit timestamps in their local timezone *without* an offset
marker. We attach a per-device IANA timezone (falling back to a global
"default source timezone" setting) and convert to UTC for storage. If the
result is implausible (>``MAX_SKEW`` from ingest time, or unparseable), we
fall back to ingest time and signal the caller so it can be counted.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

# Reject parsed times more than this far from ingest time — usually a wrong
# device clock or a misconfigured source TZ.
MAX_SKEW = timedelta(hours=24)

# Fields in ``parsed_data`` that may carry the event time, in priority order.
# ``generated_time`` is when the device's data-plane saw the event.
# ``receive_time`` is when the management plane logged it (close enough).
# Both are device-local strings on most vendors.
_CANDIDATE_FIELDS = (
    "generated_time",
    "receive_time",
    "log_datetime",
    "eventtime",
    "event_time",
)

# Vendors use a handful of common formats. Try them in order.
_FORMATS = (
    "%Y/%m/%d %H:%M:%S",       # Palo Alto:  2026/05/25 14:10:19
    "%Y-%m-%d %H:%M:%S",       # FortiGate:  2026-05-25 14:10:19
    "%Y-%m-%dT%H:%M:%S",       # ISO without ms / tz
    "%Y-%m-%dT%H:%M:%S.%f",    # ISO with ms
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%b %d %H:%M:%S",          # RFC3164: May 25 14:10:19 (no year)
)


def _zoneinfo(name: Optional[str]) -> Optional[ZoneInfo]:
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def _try_parse(s: str) -> Optional[datetime]:
    s = s.strip()
    if not s:
        return None
    # ISO with explicit offset: 2026-05-25T14:10:20.554+03:00
    if "T" in s and (s.endswith("Z") or "+" in s[10:] or "-" in s[10:]):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            pass
    for fmt in _FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def parse_event_time(
    parsed_data: Optional[dict],
    device_tz: Optional[str],
    default_tz: Optional[str],
    ingest_time: datetime,
) -> Tuple[datetime, str]:
    """Return ``(event_time_utc, source)``.

    ``source`` is one of:
      * ``"parsed"`` — taken from ``parsed_data`` and converted to UTC
      * ``"parsed_tzaware"`` — ``parsed_data`` already carried an offset
      * ``"fallback_ingest"`` — could not parse / skew too large
    """
    if not parsed_data:
        return ingest_time, "fallback_ingest"

    raw: Optional[str] = None
    for key in _CANDIDATE_FIELDS:
        v = parsed_data.get(key)
        if v:
            raw = str(v)
            break
    if raw is None:
        d = parsed_data.get("date")
        t = parsed_data.get("time")
        if d and t:
            raw = f"{d} {t}"
    if raw is None:
        return ingest_time, "fallback_ingest"

    dt = _try_parse(raw)
    if dt is None:
        return ingest_time, "fallback_ingest"

    # If the parser already attached a tz, trust it.
    tzaware = dt.tzinfo is not None
    if not tzaware:
        zi = _zoneinfo(device_tz) or _zoneinfo(default_tz) or timezone.utc
        dt = dt.replace(tzinfo=zi)
        # RFC3164 has no year — fill from ingest year, fix Dec→Jan rollover.
        if dt.year == 1900:
            dt = dt.replace(year=ingest_time.year)
            if dt - ingest_time > timedelta(days=180):
                dt = dt.replace(year=ingest_time.year - 1)

    event_utc = dt.astimezone(timezone.utc)

    skew = abs(event_utc - ingest_time)
    if skew > MAX_SKEW:
        logger.debug(
            "event_time skew %s exceeds MAX_SKEW (raw=%r tz=%s); using ingest_time",
            skew, raw, device_tz or default_tz,
        )
        return ingest_time, "fallback_ingest"

    return event_utc, ("parsed_tzaware" if tzaware else "parsed")
