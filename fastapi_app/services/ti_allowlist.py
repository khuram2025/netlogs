"""
Threat-intel allow / warning lists.

A warninglist is a set of values that look bad to a feed but are almost
certainly benign in practice — bogon ranges, public DNS resolvers, major
CDN / cloud ranges, well-known vendor domains. The allowlist also holds
analyst-cleared false positives.

Enforcement is at the sightings roll-up: a sighting whose IOC matches an
allowlist entry is recorded with status ``suppressed`` and never escalated —
the raw matches stay in ClickHouse as evidence, but the noise is kept out of
the triage queue.
"""

import ipaddress
import logging
from urllib.parse import urlparse

from sqlalchemy import select

from ..db.database import async_session_maker
from ..models.threat_intel import TIAllowlist

logger = logging.getLogger(__name__)


# Curated built-in warninglists. A practical starter set — the analyst can
# extend it, and false-positive triage adds to it. Not exhaustive (a full
# cloud-range / Tranco sync is a separate, refreshable feature).
BUILTIN_WARNINGLISTS = [
    {
        "list_name": "Bogon & Private", "entry_type": "cidr",
        "reason": "Non-routable / reserved address space",
        "values": [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
            "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/4",
            "240.0.0.0/4", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        ],
    },
    {
        "list_name": "Public DNS Resolvers", "entry_type": "ip",
        "reason": "Well-known public DNS resolver",
        "values": [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
            "149.112.112.112", "208.67.222.222", "208.67.220.220",
            "64.6.64.6", "64.6.65.6", "94.140.14.14", "94.140.15.15",
        ],
    },
    {
        "list_name": "Cloudflare", "entry_type": "cidr",
        "reason": "Cloudflare CDN range",
        "values": [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ],
    },
    {
        "list_name": "Benign Vendor Domains", "entry_type": "domain",
        "reason": "Major-vendor infrastructure / update domain",
        "values": [
            "microsoft.com", "windowsupdate.com", "msftconnecttest.com",
            "msftncsi.com", "windows.com", "office.com", "office365.com",
            "live.com", "microsoftonline.com", "google.com", "gstatic.com",
            "googleapis.com", "googleusercontent.com", "apple.com",
            "icloud.com", "akamai.net", "akamaiedge.net",
            "akamaitechnologies.com", "cloudfront.net", "amazonaws.com",
            "azureedge.net", "ubuntu.com", "mozilla.org", "digicert.com",
            "gvt1.com", "gvt2.com",
        ],
    },
]


class AllowlistChecker:
    """In-memory allow-list lookup — exact IP, CIDR, domain (with parent
    suffixes) and exact value (url / hash)."""

    def __init__(self):
        self.ips: set = set()
        self.cidrs: list = []
        self.domains: set = set()
        self.values: set = set()

    def add(self, entry_type: str, value: str):
        v = (value or "").strip()
        if not v:
            return
        if entry_type == "cidr" or (entry_type == "ip" and "/" in v):
            try:
                self.cidrs.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                pass
        elif entry_type == "ip":
            self.ips.add(v)
        elif entry_type == "domain":
            self.domains.add(v.lower().rstrip("."))
        else:
            self.values.add(v)

    def is_allowed(self, ioc_type: str, value: str) -> bool:
        if not value:
            return False
        v = str(value)
        if ioc_type == "ip":
            if v in self.ips:
                return True
            if self.cidrs:
                try:
                    ip = ipaddress.ip_address(v)
                except ValueError:
                    return False
                return any(ip in net for net in self.cidrs)
            return False
        if ioc_type == "domain":
            return self._domain_allowed(v)
        if ioc_type == "url":
            if v in self.values:
                return True
            try:
                host = urlparse(v if "://" in v else "http://" + v).hostname
            except ValueError:
                host = None
            return self._domain_allowed(host) if host else False
        return v in self.values   # hash and anything else — exact match

    def _domain_allowed(self, name: str) -> bool:
        host = str(name).lower().strip().rstrip(".")
        if not host or not self.domains:
            return False
        if host in self.domains:
            return True
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            if ".".join(labels[i:]) in self.domains:
                return True
        return False

    def count(self) -> int:
        return (len(self.ips) + len(self.cidrs)
                + len(self.domains) + len(self.values))


async def load_allowlist() -> AllowlistChecker:
    """Build an AllowlistChecker from all active allowlist entries."""
    chk = AllowlistChecker()
    try:
        async with async_session_maker() as db:
            rows = (await db.execute(
                select(TIAllowlist).where(TIAllowlist.is_active.is_(True))
            )).scalars().all()
        for r in rows:
            chk.add(r.entry_type, r.value)
    except Exception as e:
        logger.error(f"load_allowlist failed: {e}")
    return chk


async def seed_builtin_warninglists() -> int:
    """Create the built-in warninglist entries if they do not exist."""
    added = 0
    try:
        async with async_session_maker() as db:
            existing = {
                (r[0], r[1]) for r in (await db.execute(
                    select(TIAllowlist.entry_type, TIAllowlist.value))).all()
            }
            for wl in BUILTIN_WARNINGLISTS:
                for val in wl["values"]:
                    if (wl["entry_type"], val) in existing:
                        continue
                    db.add(TIAllowlist(
                        entry_type=wl["entry_type"], value=val,
                        list_name=wl["list_name"], reason=wl["reason"],
                        source="builtin", created_by="system", is_active=True,
                    ))
                    added += 1
            if added:
                await db.commit()
                logger.info(f"Seeded {added} built-in warninglist entries")
    except Exception as e:
        logger.error(f"seed_builtin_warninglists failed: {e}")
    return added
