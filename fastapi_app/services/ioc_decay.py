"""
IOC decay & expiry.

Indicators do not stay valid forever — threat actors rotate infrastructure.
Each IOC gets a type-aware lifetime: a URL is stale within weeks, an IP
within a couple of months, a file hash stays valid far longer (a hash is
immutable). ``expires_at = last_seen + the type's TTL``; a feed re-asserting
an IOC bumps ``last_seen`` and pushes expiry forward, so a live threat stays
fresh while one that drops off its feed ages out.

A scheduled job deactivates IOCs past their expiry; the matcher then stops
loading them.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from ..db.database import async_session_maker

logger = logging.getLogger(__name__)

# Type-aware decay lifetimes — days from last_seen to expiry.
DECAY_DAYS = {
    "url": 21,            # malware-payload URLs rotate fast
    "domain": 30,
    "ip": 75,             # infrastructure lasts longer than a URL
    "hash_md5": 365,      # a file hash is immutable — valid far longer
    "hash_sha1": 365,
    "hash_sha256": 365,
}
DEFAULT_DECAY_DAYS = 60


def decay_days(ioc_type: str) -> int:
    return DECAY_DAYS.get(ioc_type, DEFAULT_DECAY_DAYS)


def expiry_for(ioc_type: str, last_seen: datetime) -> datetime:
    """When an IOC of this type, last seen at ``last_seen``, should expire."""
    base = last_seen or datetime.now(timezone.utc)
    return base + timedelta(days=decay_days(ioc_type))


async def decay_iocs() -> dict:
    """Scheduler job: backfill missing expiry dates, then deactivate IOCs
    whose type-aware lifetime has elapsed."""
    backfilled = 0
    expired = 0
    try:
        async with async_session_maker() as db:
            # 1. Backfill expires_at for IOCs that never received one.
            for ioc_type in DECAY_DAYS:
                res = await db.execute(text(
                    "UPDATE iocs SET expires_at = COALESCE(last_seen, created_at) "
                    "+ make_interval(days => :d) "
                    "WHERE expires_at IS NULL AND ioc_type = :t"
                ), {"d": decay_days(ioc_type), "t": ioc_type})
                backfilled += res.rowcount or 0

            # 2. Deactivate IOCs whose lifetime has elapsed.
            res = await db.execute(text(
                "UPDATE iocs SET is_active = false "
                "WHERE is_active = true AND expires_at IS NOT NULL "
                "AND expires_at < now()"
            ))
            expired = res.rowcount or 0
            await db.commit()
    except Exception as e:
        logger.error(f"decay_iocs failed: {e}")
        return {"backfilled": 0, "expired": 0, "error": str(e)}

    if backfilled or expired:
        logger.info(f"IOC decay: backfilled {backfilled} expiry dates, "
                    f"aged out {expired} stale IOCs")
    return {"backfilled": backfilled, "expired": expired}
