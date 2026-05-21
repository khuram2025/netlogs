"""
IOC sightings roll-up.

Aggregates the raw, per-event ``ioc_matches`` (ClickHouse) into de-duplicated
``ioc_sightings`` (PostgreSQL) — one row per ``(IOC value, internal asset,
direction)``. A scheduler job runs the roll-up incrementally via a watermark;
the result is the triage queue the Sightings page shows.

The raw events stay in ClickHouse as the evidence trail behind each sighting.
"""

import hashlib
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.system_settings import SystemSetting
from ..models.threat_intel import IOCSighting

logger = logging.getLogger(__name__)

_WM_KEY = "ioc_sightings_rollup_wm"
_LAG_SECONDS = 20
_FIRST_RUN_LOOKBACK = 30 * 86400      # backfill 30 days of existing matches
_MAX_ROWS = 200_000                   # safety cap per run
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_HASH_TYPES = {"hash", "hash_md5", "hash_sha1", "hash_sha256"}

# Sentinel internal_asset for inbound sightings: a perimeter scan from one
# external actor is one triage unit, not one-per-targeted-IP. The raw events
# still carry every individual target.
PERIMETER = "perimeter"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _aware(dt):
    """Normalise a datetime to tz-aware UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _classify(ioc_type: str, matched_field: str, srcip: str, dstip: str):
    """Return ``(internal_asset, direction)`` for a raw match.

    ``outbound`` — an internal asset reached known-bad infra (likely
    compromise); keyed per host so each host is its own sighting.
    ``inbound`` — known-bad reached our attack surface; collapsed to one
    ``perimeter`` sighting per external actor (the raw events keep every
    individual target). ``internal`` — undetermined."""
    mf = (matched_field or "").lower()
    if ioc_type in _HASH_TYPES or ioc_type in ("domain", "url"):
        # Content the host reached out for — the internal host is the source.
        asset = srcip if (_is_private(srcip) or not _is_private(dstip)) else dstip
        return (asset or dstip or srcip), "outbound"
    # IP IOC — the matched_field says which end is the known-bad one.
    if mf in ("dstip", "dest_ip"):
        return (srcip or dstip), "outbound"
    if mf in ("srcip", "src_ip"):
        return PERIMETER, "inbound"
    # Unknown matched_field — infer from address privacy.
    if _is_private(dstip) and not _is_private(srcip):
        return PERIMETER, "inbound"
    if _is_private(srcip) and not _is_private(dstip):
        return srcip, "outbound"
    return (srcip or dstip), "internal"


def _key(ioc_value: str, asset: str, direction: str) -> str:
    return hashlib.sha1(
        f"{ioc_value}|{asset}|{direction}".encode("utf-8")).hexdigest()


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


def _fetch_new_matches(wm_str: str, cutoff_str: str):
    client = ClickHouseClient.get_client()
    query = (
        "SELECT timestamp, ioc_id, ioc_type, ioc_value, threat_type, severity, "
        "matched_field, srcip, dstip, feed_name, log_timestamp "
        "FROM ioc_matches "
        "WHERE timestamp > parseDateTime64BestEffort({wm:String}, 3) "
        "AND timestamp <= parseDateTime64BestEffort({cutoff:String}, 3) "
        f"ORDER BY timestamp LIMIT {_MAX_ROWS}"
    )
    return client.query(
        query, parameters={"wm": wm_str, "cutoff": cutoff_str}).result_rows


async def rollup_sightings():
    """Scheduler job: fold new ioc_matches into the sightings table."""
    cutoff_str = (datetime.now(timezone.utc)
                  - timedelta(seconds=_LAG_SECONDS)).strftime(_TS_FMT)

    async with async_session_maker() as db:
        wm = await _get_setting(db, _WM_KEY)
        if not wm:
            wm = (datetime.now(timezone.utc)
                  - timedelta(seconds=_FIRST_RUN_LOOKBACK)).strftime(_TS_FMT)
        try:
            rows = _fetch_new_matches(wm, cutoff_str)
        except Exception as e:
            logger.error(f"sightings rollup: fetch failed: {e}")
            return

        if not rows:
            await _set_setting(db, _WM_KEY, cutoff_str)
            await db.commit()
            return

        # ── Aggregate the new events by (ioc_value, asset, direction) ──
        agg: dict = {}
        for (_ts, ioc_id, ioc_type, ioc_value, threat_type, severity,
             matched_field, srcip, dstip, feed_name, log_ts) in rows:
            asset, direction = _classify(ioc_type, matched_field, srcip, dstip)
            if not asset:
                continue
            log_ts = _aware(log_ts)
            k = _key(ioc_value, asset, direction)
            g = agg.get(k)
            if g is None:
                g = {"ioc_id": ioc_id, "ioc_type": ioc_type,
                     "ioc_value": ioc_value, "threat_type": threat_type,
                     "severity": severity, "feed_name": feed_name,
                     "asset": asset, "direction": direction,
                     "hits": 0, "first": log_ts, "last": log_ts}
                agg[k] = g
            g["hits"] += 1
            if log_ts and (g["first"] is None or log_ts < g["first"]):
                g["first"] = log_ts
            if log_ts and (g["last"] is None or log_ts > g["last"]):
                g["last"] = log_ts
            if _SEV_RANK.get(severity, 1) > _SEV_RANK.get(g["severity"], 1):
                g["severity"] = severity

        # ── Upsert into ioc_sightings ──────────────────────────────────
        keys = list(agg.keys())
        existing: dict = {}
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            res = await db.execute(
                select(IOCSighting).where(IOCSighting.sighting_key.in_(chunk)))
            for s in res.scalars().all():
                existing[s.sighting_key] = s

        new_count = 0
        for k, g in agg.items():
            s = existing.get(k)
            if s:
                s.hit_count += g["hits"]
                if g["last"] and (_aware(s.last_seen) is None
                                  or g["last"] > _aware(s.last_seen)):
                    s.last_seen = g["last"]
                if g["first"] and (_aware(s.first_seen) is None
                                   or g["first"] < _aware(s.first_seen)):
                    s.first_seen = g["first"]
                if _SEV_RANK.get(g["severity"], 1) > _SEV_RANK.get(s.severity, 1):
                    s.severity = g["severity"]
            else:
                escalated = (g["direction"] == "outbound"
                             and g["severity"] in ("high", "critical"))
                db.add(IOCSighting(
                    sighting_key=k,
                    ioc_id=(g["ioc_id"] or None),
                    ioc_type=g["ioc_type"], ioc_value=g["ioc_value"],
                    threat_type=g["threat_type"], severity=g["severity"],
                    feed_name=g["feed_name"], internal_asset=g["asset"],
                    direction=g["direction"], hit_count=g["hits"],
                    first_seen=g["first"], last_seen=g["last"],
                    status="new", escalated=escalated,
                ))
                new_count += 1

        # Watermark: if the row cap was hit there may be more — resume from the
        # last recorded-at; otherwise the whole window is done.
        if len(rows) >= _MAX_ROWS:
            last_ts = _aware(rows[-1][0])
            new_wm = last_ts.strftime(_TS_FMT) if last_ts else cutoff_str
        else:
            new_wm = cutoff_str
        await _set_setting(db, _WM_KEY, new_wm)
        await db.commit()

    logger.info(
        f"sightings rollup: {len(rows)} matches -> {len(agg)} groups, "
        f"{new_count} new")


async def get_sighting_events(ioc_value: str, internal_asset: str,
                              direction: str = "inbound",
                              limit: int = 100) -> list:
    """The raw ioc_matches behind a sighting — its evidence trail.

    An inbound (``perimeter``) sighting returns every event for the actor;
    an outbound sighting is scoped to the one internal asset."""
    try:
        client = ClickHouseClient.get_client()
        if direction == "inbound" or internal_asset == PERIMETER:
            where = "ioc_value = {v:String}"
            params = {"v": ioc_value, "n": int(limit)}
        else:
            where = ("ioc_value = {v:String} "
                     "AND (srcip = {a:String} OR dstip = {a:String})")
            params = {"v": ioc_value, "a": internal_asset, "n": int(limit)}
        rows = client.query(
            "SELECT log_timestamp, srcip, dstip, srcport, dstport, "
            "matched_field, action, device_ip, feed_name "
            f"FROM ioc_matches WHERE {where} "
            "ORDER BY log_timestamp DESC LIMIT {n:UInt32}",
            parameters=params,
        ).result_rows
        return [
            {"log_timestamp": str(r[0]), "srcip": r[1], "dstip": r[2],
             "srcport": r[3], "dstport": r[4], "matched_field": r[5],
             "action": r[6], "device_ip": str(r[7]), "feed_name": r[8]}
            for r in rows
        ]
    except Exception as e:
        logger.error(f"get_sighting_events failed: {e}")
        return []
