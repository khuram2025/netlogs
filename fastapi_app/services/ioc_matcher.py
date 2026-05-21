"""
Real-Time IOC Matcher - In-memory lookup for high-speed IOC matching.

Uses sets for O(1) IP lookup and dict for domain matching.
Designed to add < 1ms overhead per log entry.
"""

import logging
import ipaddress
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class IOCMatcher:
    """
    Thread-safe in-memory IOC matcher with periodic cache refresh.

    Data structures:
    - IP IOCs: frozenset for O(1) lookup
    - Domain IOCs: dict for exact + subdomain matching
    - Hash IOCs: frozenset for O(1) lookup
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # IOC lookup structures
        self._ip_iocs: Dict[str, dict] = {}       # ip_string -> ioc_info
        self._domain_iocs: Dict[str, dict] = {}    # domain -> ioc_info
        self._url_iocs: Dict[str, dict] = {}       # url -> ioc_info
        self._hash_iocs: Dict[str, dict] = {}      # hash_value -> ioc_info

        # Fast lookup sets (just values for O(1) membership test)
        self._ip_set: frozenset = frozenset()
        self._domain_set: frozenset = frozenset()
        self._url_set: frozenset = frozenset()
        self._hash_set: frozenset = frozenset()

        # CIDR networks for subnet matching
        self._cidr_networks: List[Tuple[ipaddress.IPv4Network, dict]] = []

        self._last_refresh = 0.0
        self._refresh_interval = 300  # 5 minutes
        self._stats = {"checks": 0, "matches": 0, "errors": 0}
        self._data_lock = threading.RLock()

    def load_iocs(self, grouped_iocs: Dict[str, List[dict]]):
        """Load IOCs from grouped dict into memory structures."""
        with self._data_lock:
            # Build IP lookup
            ip_iocs = {}
            cidr_networks = []
            for ioc in grouped_iocs.get("ip", []):
                val = ioc["value"]
                if "/" in val:
                    # CIDR notation
                    try:
                        net = ipaddress.ip_network(val, strict=False)
                        cidr_networks.append((net, ioc))
                    except ValueError:
                        pass
                else:
                    ip_iocs[val] = ioc

            # Build domain lookup
            domain_iocs = {}
            for ioc in grouped_iocs.get("domain", []):
                domain_iocs[ioc["value"].lower()] = ioc

            # Build URL lookup (exact match)
            url_iocs = {}
            for ioc in grouped_iocs.get("url", []):
                url_iocs[ioc["value"]] = ioc

            # Build hash lookup (combine all hash types)
            hash_iocs = {}
            for hash_type in ("hash_md5", "hash_sha1", "hash_sha256"):
                for ioc in grouped_iocs.get(hash_type, []):
                    hash_iocs[ioc["value"].lower()] = ioc

            self._ip_iocs = ip_iocs
            self._ip_set = frozenset(ip_iocs.keys())
            self._cidr_networks = cidr_networks
            self._domain_iocs = domain_iocs
            self._domain_set = frozenset(domain_iocs.keys())
            self._url_iocs = url_iocs
            self._url_set = frozenset(url_iocs.keys())
            self._hash_iocs = hash_iocs
            self._hash_set = frozenset(hash_iocs.keys())
            self._last_refresh = time.time()

            total = (len(ip_iocs) + len(cidr_networks) + len(domain_iocs)
                     + len(url_iocs) + len(hash_iocs))
            logger.info(
                f"IOC matcher loaded: {len(ip_iocs)} IPs, {len(cidr_networks)} CIDRs, "
                f"{len(domain_iocs)} domains, {len(url_iocs)} URLs, "
                f"{len(hash_iocs)} hashes (total: {total})"
            )

    # ── Single-value matchers (shared by check_log and the batch sweep) ──

    def _match_ip(self, ip: str) -> Optional[dict]:
        """Match an IP against exact IP IOCs, then CIDR ranges."""
        if not ip:
            return None
        ioc = self._ip_iocs.get(ip)
        if ioc:
            return ioc
        if self._cidr_networks:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, cidr_ioc in self._cidr_networks:
                if ip_obj in net:
                    return cidr_ioc
        return None

    def _match_domain(self, name: str) -> Optional[dict]:
        """Match a hostname against domain IOCs — exact, then parent suffixes,
        so a domain IOC also matches its subdomains."""
        if not name or not self._domain_set:
            return None
        host = str(name).strip().rstrip(".").lower()
        if not host:
            return None
        ioc = self._domain_iocs.get(host)
        if ioc:
            return ioc
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            ioc = self._domain_iocs.get(".".join(labels[i:]))
            if ioc:
                return ioc
        return None

    def _match_url(self, url: str) -> Optional[dict]:
        """Match a URL exactly, then fall back to its host as a domain IOC."""
        if not url or not (self._url_set or self._domain_set):
            return None
        ioc = self._url_iocs.get(url) or self._url_iocs.get(url.rstrip("/"))
        if ioc:
            return ioc
        try:
            host = urlparse(url if "://" in url else "http://" + url).hostname
        except ValueError:
            host = None
        return self._match_domain(host) if host else None

    def _match_hash(self, value: str) -> Optional[dict]:
        """Match a file hash (any algorithm) — exact, case-insensitive."""
        if not value:
            return None
        return self._hash_iocs.get(str(value).strip().lower())

    def check_value(self, value: str, kind: str) -> Optional[dict]:
        """Match one value of a given kind (ip / domain / url / hash).
        The batch log sweep uses this for the non-firewall log streams."""
        if not value:
            return None
        if kind == "ip":
            return self._match_ip(value)
        if kind == "domain":
            return self._match_domain(value)
        if kind == "url":
            return self._match_url(value)
        if kind == "hash":
            return self._match_hash(value)
        return None

    def total_iocs(self) -> int:
        """Total IOCs currently held in memory across all types."""
        return (len(self._ip_iocs) + len(self._cidr_networks)
                + len(self._domain_iocs) + len(self._url_iocs)
                + len(self._hash_iocs))

    def check_log(self, srcip: str, dstip: str, **kwargs) -> List[dict]:
        """Check a firewall log's src/dst IPs against IP IOCs.
        Hot path on the syslog pipeline — kept minimal."""
        self._stats["checks"] += 1
        matches = []
        try:
            for ip, field in ((srcip, "srcip"), (dstip, "dstip")):
                ioc = self._match_ip(ip)
                if ioc:
                    matches.append({"matched_field": field, **ioc})
        except Exception as e:
            self._stats["errors"] += 1
            if self._stats["errors"] % 1000 == 1:
                logger.error(f"IOC matcher error: {e}")
        if matches:
            self._stats["matches"] += len(matches)
        return matches

    def needs_refresh(self) -> bool:
        """Check if the IOC cache needs refreshing."""
        return (time.time() - self._last_refresh) > self._refresh_interval

    def get_stats(self) -> dict:
        """Get matcher statistics."""
        with self._data_lock:
            return {
                "total_iocs": self.total_iocs(),
                "ip_count": len(self._ip_iocs),
                "cidr_count": len(self._cidr_networks),
                "domain_count": len(self._domain_iocs),
                "url_count": len(self._url_iocs),
                "hash_count": len(self._hash_iocs),
                "checks": self._stats["checks"],
                "matches": self._stats["matches"],
                "errors": self._stats["errors"],
                "last_refresh": self._last_refresh,
            }


# Module-level singleton
_matcher = IOCMatcher()


def get_matcher() -> IOCMatcher:
    """Get the global IOC matcher instance."""
    return _matcher


async def refresh_ioc_cache():
    """Refresh the in-memory IOC cache from the database."""
    try:
        from .threat_intel_service import get_all_active_iocs
        grouped = await get_all_active_iocs()
        _matcher.load_iocs(grouped)
    except Exception as e:
        logger.error(f"Failed to refresh IOC cache: {e}")


def check_and_record_matches(
    srcip: str,
    dstip: str,
    log_timestamp,
    device_ip: str,
    srcport: int = 0,
    dstport: int = 0,
    action: str = "",
):
    """
    Check a log entry against IOCs and record any matches.
    Called from the syslog collector pipeline.
    Returns True if any match was found.
    """
    matches = _matcher.check_log(srcip=srcip, dstip=dstip)
    if not matches:
        return False

    # Record matches and auto-block high-confidence hits
    for match in matches:
        try:
            from .threat_intel_service import insert_ioc_match
            insert_ioc_match({
                "ioc_id": match.get("id", 0),
                "ioc_type": match.get("ioc_type", "ip"),
                "ioc_value": match.get("value", ""),
                "threat_type": match.get("threat_type", "unknown"),
                "severity": match.get("severity", "medium"),
                "confidence": match.get("confidence", 50),
                "matched_field": match.get("matched_field", ""),
                "log_timestamp": log_timestamp,
                "device_ip": device_ip,
                "srcip": srcip or "",
                "dstip": dstip or "",
                "srcport": srcport,
                "dstport": dstport,
                "action": action or "",
                "feed_name": match.get("source", ""),
            })
        except Exception as e:
            logger.error(f"Failed to record IOC match: {e}")

        # Auto-block: queue high-confidence IP matches for EDL addition
        try:
            confidence = match.get("confidence", 50)
            severity = match.get("severity", "medium")
            if (confidence >= AUTO_BLOCK_CONFIDENCE_THRESHOLD
                    and severity in AUTO_BLOCK_SEVERITY_LEVELS
                    and match.get("ioc_type") == "ip"):
                matched_ip = match.get("value", "")
                if matched_ip and matched_ip not in _auto_block_seen:
                    _auto_block_queue.append({
                        "ip": matched_ip,
                        "confidence": confidence,
                        "severity": severity,
                        "threat_type": match.get("threat_type", "unknown"),
                        "source": match.get("source", ""),
                    })
                    _auto_block_seen.add(matched_ip)
        except Exception:
            pass  # Never block the pipeline

    return True


# ============ Auto-Block EDL Integration ============

AUTO_BLOCK_CONFIDENCE_THRESHOLD = 80
AUTO_BLOCK_SEVERITY_LEVELS = {"critical", "high"}
AUTO_BLOCK_EXPIRY_HOURS = 24
AUTO_BLOCK_EDL_NAME = "Threat Intel Auto-Block"

# In-memory queue for deferred EDL writes (don't block pipeline)
_auto_block_queue: List[dict] = []
_auto_block_seen: Set[str] = set()


async def ensure_auto_block_edl():
    """Create the Auto-Block EDL list if it doesn't exist."""
    try:
        from ..db.database import async_session_maker
        from ..models.edl import EDLList, EDLType
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(EDLList).where(EDLList.name == AUTO_BLOCK_EDL_NAME)
            )
            edl = result.scalar_one_or_none()
            if not edl:
                import secrets
                edl = EDLList(
                    name=AUTO_BLOCK_EDL_NAME,
                    description="Automatically populated from high-confidence IOC matches. "
                                f"Threshold: confidence >= {AUTO_BLOCK_CONFIDENCE_THRESHOLD}%, "
                                f"severity: {', '.join(AUTO_BLOCK_SEVERITY_LEVELS)}. "
                                f"Entries expire after {AUTO_BLOCK_EXPIRY_HOURS} hours.",
                    list_type=EDLType.IP,
                    is_active=True,
                    access_token=secrets.token_urlsafe(32),
                )
                db.add(edl)
                await db.commit()
                logger.info(f"Created Auto-Block EDL list (id={edl.id})")
            else:
                logger.info(f"Auto-Block EDL list already exists (id={edl.id})")
            return edl.id
    except Exception as e:
        logger.error(f"Failed to ensure auto-block EDL: {e}")
        return None


async def process_auto_block_queue():
    """
    Process the auto-block queue and add entries to the EDL.
    Called periodically by the scheduler (every 30 seconds).
    """
    global _auto_block_queue

    if not _auto_block_queue:
        return

    # Swap the queue atomically
    queue = _auto_block_queue
    _auto_block_queue = []

    try:
        from ..db.database import async_session_maker
        from ..models.edl import EDLList, EDLEntry
        from sqlalchemy import select

        async with async_session_maker() as db:
            # Get the auto-block EDL
            result = await db.execute(
                select(EDLList).where(EDLList.name == AUTO_BLOCK_EDL_NAME)
            )
            edl = result.scalar_one_or_none()
            if not edl:
                return

            added = 0
            for item in queue:
                ip = item["ip"]

                # Check for existing entry
                existing = await db.execute(
                    select(EDLEntry).where(
                        EDLEntry.edl_list_id == edl.id,
                        EDLEntry.value == ip
                    )
                )
                if existing.scalar_one_or_none():
                    continue

                entry = EDLEntry(
                    edl_list_id=edl.id,
                    value=ip,
                    description=(
                        f"Auto-blocked: {item['threat_type']} "
                        f"(confidence: {item['confidence']}%, severity: {item['severity']}, "
                        f"feed: {item['source']})"
                    ),
                    is_active=True,
                    source="auto_block",
                    expires_at=datetime.utcnow() + timedelta(hours=AUTO_BLOCK_EXPIRY_HOURS)
                        if AUTO_BLOCK_EXPIRY_HOURS > 0 else None,
                )
                db.add(entry)
                added += 1

            if added > 0:
                await db.commit()
                logger.info(f"Auto-block EDL: added {added} IPs (queue had {len(queue)} items)")

    except Exception as e:
        logger.error(f"Failed to process auto-block queue: {e}")
