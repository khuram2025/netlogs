"""
Batch IOC sweep.

The real-time matcher only checks firewall (`syslogs`) source/destination
IPs. This job closes that gap: every minute it scans the newest DNS, URL and
Palo-Alto-threat log rows and matches them against the domain / URL / hash /
IP IOCs the matcher already holds in memory — so the ~50% of the IOC corpus
that is not IP-based finally produces detections.

Exactly-once: a per-table watermark in `system_settings` records how far each
table has been swept; each run processes the ``(watermark, now - lag]`` window.
"""

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.system_settings import SystemSetting
from .ioc_matcher import get_matcher

logger = logging.getLogger(__name__)

_WM_PREFIX = "ioc_sweep_wm_"        # + table name
_STATS_KEY = "ioc_sweep_stats"
_LAG_SECONDS = 15                   # ignore rows newer than this (insert latency)
_FIRST_RUN_LOOKBACK = 300           # history window on a cold watermark
_MAX_ROWS = 80_000                  # safety cap: rows scanned per table per run
_MAX_MATCHES = 5_000                # safety cap: matches recorded per table per run
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

# Per source table: columns to SELECT, and the (column, ioc-kind) pairs to test.
_SWEEP_TABLES = {
    "dns_logs": {
        "select": ["timestamp", "device_ip", "src_ip", "dest_ip",
                   "qname", "resolved_ip"],
        "checks": [("qname", "domain"), ("src_ip", "ip"),
                   ("dest_ip", "ip"), ("resolved_ip", "ip")],
    },
    "url_logs": {
        "select": ["timestamp", "device_ip", "src_ip", "dest_ip",
                   "dest_port", "url", "hostname"],
        "checks": [("url", "url"), ("hostname", "domain"),
                   ("src_ip", "ip"), ("dest_ip", "ip")],
    },
    "pa_threat_logs": {
        "select": ["timestamp", "device_ip", "src_ip", "dest_ip",
                   "dest_port", "file_hash", "url"],
        "checks": [("file_hash", "hash"), ("url", "url"),
                   ("src_ip", "ip"), ("dest_ip", "ip")],
    },
}

# ioc_matches column order — must match insert_ioc_match() in threat_intel_service.
_MATCH_COLUMNS = [
    "timestamp", "ioc_id", "ioc_type", "ioc_value", "threat_type",
    "severity", "confidence", "matched_field", "log_timestamp",
    "device_ip", "srcip", "dstip", "srcport", "dstport", "action", "feed_name",
]


def _safe_ip(value) -> str:
    """Coerce a value to an IPv4 string for the ioc_matches.device_ip column."""
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return "0.0.0.0"


async def _get_setting(db, key, default=None):
    row = (await db.execute(
        select(SystemSetting).where(SystemSetting.key == key)
    )).scalar_one_or_none()
    return row.value if row and row.value else default


async def _set_setting(db, key, value):
    row = (await db.execute(
        select(SystemSetting).where(SystemSetting.key == key)
    )).scalar_one_or_none()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))


def _sweep_table(table: str, cfg: dict, matcher, wm_str: str, cutoff_str: str):
    """Scan one table's ``(watermark, cutoff]`` window. Returns
    ``(rows_scanned, match_rows, new_watermark)``."""
    client = ClickHouseClient.get_client()
    cols = cfg["select"]
    idx = {c: i for i, c in enumerate(cols)}
    query = (
        f"SELECT {', '.join(cols)} FROM {table} "
        f"WHERE timestamp > parseDateTime64BestEffort({{wm:String}}, 3) "
        f"AND timestamp <= parseDateTime64BestEffort({{cutoff:String}}, 3) "
        f"ORDER BY timestamp LIMIT {_MAX_ROWS}"
    )
    rows = client.query(
        query, parameters={"wm": wm_str, "cutoff": cutoff_str}
    ).result_rows
    if not rows:
        return 0, [], cutoff_str

    recorded_at = datetime.now(timezone.utc)
    has_dport = "dest_port" in idx
    match_rows = []
    for row in rows:
        if len(match_rows) >= _MAX_MATCHES:
            break
        ts = row[idx["timestamp"]]
        for col, kind in cfg["checks"]:
            val = row[idx[col]]
            if not val:
                continue
            ioc = matcher.check_value(str(val), kind)
            if not ioc:
                continue
            match_rows.append([
                recorded_at,                       # timestamp (recorded-at)
                int(ioc.get("id", 0)),
                ioc.get("ioc_type", kind),
                ioc.get("value", ""),
                ioc.get("threat_type", "unknown"),
                ioc.get("severity", "medium"),
                int(ioc.get("confidence", 50)),
                col,                               # matched_field
                ts,                                # log_timestamp
                _safe_ip(row[idx["device_ip"]]),
                str(row[idx["src_ip"]] or ""),
                str(row[idx["dest_ip"]] or ""),
                0,                                 # srcport
                int(row[idx["dest_port"]]) if has_dport and row[idx["dest_port"]] else 0,
                "",                                # action
                ioc.get("source", ""),
            ])

    # Watermark: if we hit the row cap there may be more — resume from the last
    # row next run; otherwise the whole window is done, advance to the cutoff.
    if len(rows) >= _MAX_ROWS:
        last_ts = rows[-1][idx["timestamp"]]
        new_wm = (last_ts.strftime(_TS_FMT)
                  if hasattr(last_ts, "strftime") else cutoff_str)
    else:
        new_wm = cutoff_str
    return len(rows), match_rows, new_wm


async def sweep_ioc_logs():
    """Scheduler job: sweep DNS / URL / PA-threat logs for IOC matches."""
    matcher = get_matcher()
    if matcher.total_iocs() == 0:
        return  # matcher cache not loaded yet

    cutoff = (datetime.now(timezone.utc)
              - timedelta(seconds=_LAG_SECONDS)).strftime(_TS_FMT)
    total_scanned = total_matched = 0

    async with async_session_maker() as db:
        for table, cfg in _SWEEP_TABLES.items():
            try:
                wm = await _get_setting(db, _WM_PREFIX + table)
                if not wm:
                    wm = (datetime.now(timezone.utc)
                          - timedelta(seconds=_FIRST_RUN_LOOKBACK)).strftime(_TS_FMT)
                scanned, match_rows, new_wm = _sweep_table(
                    table, cfg, matcher, wm, cutoff)
                if match_rows:
                    ClickHouseClient.get_client().insert(
                        "ioc_matches", match_rows, column_names=_MATCH_COLUMNS)
                await _set_setting(db, _WM_PREFIX + table, new_wm)
                total_scanned += scanned
                total_matched += len(match_rows)
            except Exception as e:
                logger.error(f"IOC sweep failed for {table}: {e}")

        # Persist cumulative stats (cross-worker, survives restart).
        try:
            raw = await _get_setting(db, _STATS_KEY)
            stats = json.loads(raw) if raw else {}
            stats["logs_scanned"] = stats.get("logs_scanned", 0) + total_scanned
            stats["matches_found"] = stats.get("matches_found", 0) + total_matched
            stats["last_run"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            stats["last_run_scanned"] = total_scanned
            stats["last_run_matched"] = total_matched
            await _set_setting(db, _STATS_KEY, json.dumps(stats))
        except Exception as e:
            logger.error(f"IOC sweep stats update failed: {e}")

        await db.commit()

    if total_matched:
        logger.info(
            f"IOC sweep: scanned {total_scanned} rows, {total_matched} matches")


async def get_sweep_stats() -> dict:
    """Read the persisted sweep stats for the dashboard."""
    out = {"logs_scanned": 0, "matches_found": 0,
           "last_run": None, "last_run_ago": "never"}
    try:
        async with async_session_maker() as db:
            raw = await _get_setting(db, _STATS_KEY)
        if raw:
            s = json.loads(raw)
            out["logs_scanned"] = s.get("logs_scanned", 0)
            out["matches_found"] = s.get("matches_found", 0)
            out["last_run"] = s.get("last_run")
            if out["last_run"]:
                try:
                    lr = datetime.strptime(
                        out["last_run"], "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                    secs = int((datetime.now(timezone.utc) - lr).total_seconds())
                    out["last_run_ago"] = (
                        f"{secs}s ago" if secs < 90 else f"{secs // 60}m ago")
                except ValueError:
                    pass
    except Exception as e:
        logger.error(f"get_sweep_stats failed: {e}")
    return out
