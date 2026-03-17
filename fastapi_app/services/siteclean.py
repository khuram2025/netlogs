"""SiteClean — URL noise filtering engine.

Reads active rules from PostgreSQL, generates ClickHouse WHERE exclusion
clauses at query time.  No data is ever deleted — filtering is purely at
query time so raw data remains available for forensics.
"""

import logging
import time

from sqlalchemy import select

from ..db.database import async_session_maker
from ..models.url_clean import URLCleanRule

logger = logging.getLogger(__name__)

# ── In-memory cache ──────────────────────────────────────────────────
_cache: dict = {"rules": [], "expires": 0}
CACHE_TTL = 60  # seconds


async def _load_active_rules() -> list[tuple]:
    """Load enabled rules from PostgreSQL (with in-memory cache)."""
    now = time.time()
    if _cache["rules"] and now < _cache["expires"]:
        return _cache["rules"]

    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(URLCleanRule.rule_type, URLCleanRule.pattern)
                .where(URLCleanRule.enabled.is_(True))
            )
            rules = result.all()
            _cache["rules"] = [(r.rule_type, r.pattern) for r in rules]
            _cache["expires"] = now + CACHE_TTL
            return _cache["rules"]
    except Exception as e:
        logger.error(f"Failed to load SiteClean rules: {e}")
        return []


def invalidate_cache():
    """Call after any rule CRUD to bust the cache."""
    _cache["rules"] = []
    _cache["expires"] = 0


def _safe_pattern(pattern: str) -> str:
    """Escape single quotes for safe interpolation into ClickHouse SQL."""
    return pattern.replace("\\", "\\\\").replace("'", "\\'")


async def build_siteclean_where() -> str:
    """Build ClickHouse WHERE exclusion clause from active rules.

    Returns empty string if no rules, or a string like:
    ``AND NOT (hostname = 'x' OR hostname LIKE '%y' OR ...)``
    """
    rules = await _load_active_rules()
    if not rules:
        return ""

    clauses = []
    for rule_type, pattern in rules:
        safe = _safe_pattern(pattern)
        if rule_type == "hostname_exact":
            clauses.append(f"hostname = '{safe}'")
        elif rule_type == "hostname_glob":
            like = safe.replace("*", "%").replace("?", "_")
            clauses.append(f"hostname LIKE '{like}'")
        elif rule_type == "category":
            clauses.append(f"url_category = '{safe}'")
        elif rule_type == "url_contains":
            clauses.append(f"url LIKE '%{safe}%'")

    if not clauses:
        return ""

    combined = " OR ".join(clauses)
    return f"AND NOT ({combined})"


async def build_siteclean_match_where() -> str:
    """Same as build_siteclean_where but WITHOUT the NOT — matches noise only.

    Used by the noise-count endpoint.
    """
    rules = await _load_active_rules()
    if not rules:
        return ""

    clauses = []
    for rule_type, pattern in rules:
        safe = _safe_pattern(pattern)
        if rule_type == "hostname_exact":
            clauses.append(f"hostname = '{safe}'")
        elif rule_type == "hostname_glob":
            like = safe.replace("*", "%").replace("?", "_")
            clauses.append(f"hostname LIKE '{like}'")
        elif rule_type == "category":
            clauses.append(f"url_category = '{safe}'")
        elif rule_type == "url_contains":
            clauses.append(f"url LIKE '%{safe}%'")

    if not clauses:
        return ""

    combined = " OR ".join(clauses)
    return f"AND ({combined})"


# ── Builtin rules shipped with the system ────────────────────────────

BUILTIN_RULES = [
    # Certificate Services
    ("hostname_glob", "ocsp.*", "OCSP Checks", "Certificate Services"),
    ("hostname_glob", "crl.*", "CRL Downloads", "Certificate Services"),
    ("hostname_exact", "certificates.godaddy.com", "GoDaddy Certs", "Certificate Services"),
    ("hostname_exact", "crl.godaddy.com", "GoDaddy CRL", "Certificate Services"),
    ("hostname_glob", "crl*.digicert.com", "DigiCert CRL", "Certificate Services"),
    ("hostname_exact", "ctldl.windowsupdate.com", "MS Certificate Trust List", "Certificate Services"),

    # Windows / Microsoft Telemetry
    ("hostname_glob", "*watson*.microsoft.com", "MS Watson Telemetry", "OS Telemetry"),
    ("hostname_exact", "settings-win.data.microsoft.com", "Windows Settings Telemetry", "OS Telemetry"),
    ("hostname_exact", "www.msftconnecttest.com", "MS Connectivity Check", "Connectivity Checks"),
    ("hostname_exact", "connectivitycheck.gstatic.com", "Google Connectivity Check", "Connectivity Checks"),
    ("hostname_exact", "captive.apple.com", "Apple Captive Portal", "Connectivity Checks"),
    ("hostname_exact", "detectportal.firefox.com", "Firefox Captive Portal", "Connectivity Checks"),

    # OS Updates / Delivery
    ("hostname_glob", "*.delivery.mp.microsoft.com", "MS Delivery Optimization", "OS Updates"),
    ("hostname_glob", "*.windowsupdate.com", "Windows Update", "OS Updates"),
    ("hostname_glob", "*.update.microsoft.com", "Microsoft Update", "OS Updates"),

    # Security Software
    ("hostname_glob", "*trendmicro.com", "TrendMicro Callbacks", "Security Software"),
    ("hostname_glob", "*.symantecliveupdate.com", "Symantec LiveUpdate", "Security Software"),
    ("hostname_glob", "*.sophos.com", "Sophos Updates", "Security Software"),
    ("hostname_glob", "*.kaspersky.com", "Kaspersky Updates", "Security Software"),

    # Printer / IoT Devices
    ("hostname_glob", "signal.pod*.avatar.ext.hp.com", "HP Printer Telemetry", "Device Signals"),

    # Auto-discovery
    ("url_contains", "/autodiscover/", "Exchange Autodiscover", "Auto-discovery"),
    ("hostname_glob", "wpad.*", "WPAD Proxy Discovery", "Auto-discovery"),

    # Internal Traffic
    ("category", "private-ip-addresses", "Internal IP Addresses", "Internal Traffic"),

    # CDN / Infrastructure
    ("hostname_glob", "*.gstatic.com", "Google Static CDN", "CDN / Static"),
    ("hostname_glob", "*.akamaiedge.net", "Akamai Edge CDN", "CDN / Static"),

    # Ads / Tracking (common noise)
    ("hostname_glob", "*.doubleclick.net", "DoubleClick Ads", "Ads / Tracking"),
    ("hostname_glob", "*.googlesyndication.com", "Google Syndication", "Ads / Tracking"),
    ("hostname_glob", "*.adnxs.com", "AppNexus Ads", "Ads / Tracking"),
]


async def seed_builtin_rules():
    """Insert builtin rules that don't already exist (idempotent by label)."""
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                select(URLCleanRule.label).where(URLCleanRule.is_builtin.is_(True))
            )
            existing = {r.label for r in result.all()}

            added = 0
            for rule_type, pattern, label, group_name in BUILTIN_RULES:
                if label not in existing:
                    session.add(URLCleanRule(
                        rule_type=rule_type,
                        pattern=pattern,
                        label=label,
                        group_name=group_name,
                        enabled=True,
                        is_builtin=True,
                    ))
                    added += 1

            if added:
                await session.commit()
                logger.info(f"SiteClean: seeded {added} builtin rules")
            else:
                logger.debug("SiteClean: all builtin rules already exist")
        except Exception as e:
            await session.rollback()
            logger.error(f"SiteClean seed error: {e}")
