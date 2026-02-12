"""
Threat Intelligence Service - Feed ingestion, IOC management, and matching.

Handles fetching IOCs from external feeds, storing them, and providing
lookup capabilities for the real-time IOC matcher.
"""

import csv
import io
import json
import logging
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

import httpx
from sqlalchemy import select, func, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.threat_intel import ThreatFeed, IOC, IOCType, IOCSeverity, FeedType

logger = logging.getLogger(__name__)

# Thread pool for blocking HTTP requests
_executor = ThreadPoolExecutor(max_workers=4)


# ============ ClickHouse Table Setup ============

def ensure_ioc_matches_table():
    """Create the ioc_matches table in ClickHouse if it doesn't exist."""
    try:
        client = ClickHouseClient.get_client()
        client.command("""
            CREATE TABLE IF NOT EXISTS ioc_matches (
                timestamp DateTime64(3),
                ioc_id UInt32,
                ioc_type String,
                ioc_value String,
                threat_type String,
                severity String,
                confidence UInt8,
                matched_field String,
                log_timestamp DateTime64(3),
                device_ip IPv4,
                srcip String,
                dstip String,
                srcport UInt16,
                dstport UInt16,
                action String,
                feed_name String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, ioc_value)
            TTL toDateTime(timestamp) + INTERVAL 6 MONTH DELETE
        """)
        logger.info("IOC matches table ensured in ClickHouse")
    except Exception as e:
        logger.error(f"Failed to create ioc_matches table: {e}")


def insert_ioc_match(match_data: dict):
    """Insert a single IOC match record into ClickHouse."""
    try:
        client = ClickHouseClient.get_client()
        now = datetime.now(timezone.utc)
        client.insert("ioc_matches",
            [[
                now,
                match_data.get("ioc_id", 0),
                match_data.get("ioc_type", ""),
                match_data.get("ioc_value", ""),
                match_data.get("threat_type", ""),
                match_data.get("severity", "medium"),
                match_data.get("confidence", 50),
                match_data.get("matched_field", ""),
                match_data.get("log_timestamp", now),
                match_data.get("device_ip", "0.0.0.0"),
                match_data.get("srcip", ""),
                match_data.get("dstip", ""),
                match_data.get("srcport", 0),
                match_data.get("dstport", 0),
                match_data.get("action", ""),
                match_data.get("feed_name", ""),
            ]],
            column_names=[
                "timestamp", "ioc_id", "ioc_type", "ioc_value", "threat_type",
                "severity", "confidence", "matched_field", "log_timestamp",
                "device_ip", "srcip", "dstip", "srcport", "dstport",
                "action", "feed_name"
            ]
        )
    except Exception as e:
        logger.error(f"Failed to insert IOC match: {e}")


def get_ioc_match_stats(hours: int = 24) -> dict:
    """Get IOC match statistics for the dashboard."""
    try:
        client = ClickHouseClient.get_client()

        total = client.command(f"""
            SELECT count() FROM ioc_matches
            WHERE timestamp > now() - INTERVAL {hours} HOUR
        """)

        by_severity = client.query(f"""
            SELECT severity, count() as cnt FROM ioc_matches
            WHERE timestamp > now() - INTERVAL {hours} HOUR
            GROUP BY severity ORDER BY cnt DESC
        """)

        by_type = client.query(f"""
            SELECT ioc_type, count() as cnt FROM ioc_matches
            WHERE timestamp > now() - INTERVAL {hours} HOUR
            GROUP BY ioc_type ORDER BY cnt DESC
        """)

        recent = client.query(f"""
            SELECT timestamp, ioc_type, ioc_value, threat_type, severity,
                   confidence, matched_field, srcip, dstip, dstport, feed_name
            FROM ioc_matches
            WHERE timestamp > now() - INTERVAL {hours} HOUR
            ORDER BY timestamp DESC LIMIT 50
        """)

        return {
            "total_matches": total,
            "by_severity": [{"severity": r[0], "count": r[1]} for r in by_severity.result_rows],
            "by_type": [{"ioc_type": r[0], "count": r[1]} for r in by_type.result_rows],
            "recent_matches": [
                {
                    "timestamp": r[0],
                    "ioc_type": r[1],
                    "ioc_value": r[2],
                    "threat_type": r[3],
                    "severity": r[4],
                    "confidence": r[5],
                    "matched_field": r[6],
                    "srcip": r[7],
                    "dstip": r[8],
                    "dstport": r[9],
                    "feed_name": r[10],
                }
                for r in recent.result_rows
            ],
        }
    except Exception as e:
        logger.error(f"Failed to get IOC match stats: {e}")
        return {"total_matches": 0, "by_severity": [], "by_type": [], "recent_matches": []}


def get_ioc_matches_paginated(
    page: int = 1,
    per_page: int = 50,
    severity: Optional[str] = None,
    ioc_type: Optional[str] = None,
    hours: int = 24,
) -> Tuple[list, int]:
    """Get paginated IOC matches from ClickHouse."""
    try:
        client = ClickHouseClient.get_client()
        conditions = [f"timestamp > now() - INTERVAL {hours} HOUR"]
        if severity:
            conditions.append(f"severity = '{severity}'")
        if ioc_type:
            conditions.append(f"ioc_type = '{ioc_type}'")
        where = " AND ".join(conditions)

        total = client.command(f"SELECT count() FROM ioc_matches WHERE {where}")

        offset = (page - 1) * per_page
        rows = client.query(f"""
            SELECT timestamp, ioc_id, ioc_type, ioc_value, threat_type, severity,
                   confidence, matched_field, log_timestamp, device_ip, srcip, dstip,
                   srcport, dstport, action, feed_name
            FROM ioc_matches WHERE {where}
            ORDER BY timestamp DESC
            LIMIT {per_page} OFFSET {offset}
        """)

        matches = [
            {
                "timestamp": r[0],
                "ioc_id": r[1],
                "ioc_type": r[2],
                "ioc_value": r[3],
                "threat_type": r[4],
                "severity": r[5],
                "confidence": r[6],
                "matched_field": r[7],
                "log_timestamp": r[8],
                "device_ip": str(r[9]),
                "srcip": r[10],
                "dstip": r[11],
                "srcport": r[12],
                "dstport": r[13],
                "action": r[14],
                "feed_name": r[15],
            }
            for r in rows.result_rows
        ]
        return matches, total
    except Exception as e:
        logger.error(f"Failed to get IOC matches: {e}")
        return [], 0


# ============ Feed Fetching ============

async def fetch_feed(feed: ThreatFeed) -> Tuple[int, str]:
    """
    Fetch and parse IOCs from a threat feed.
    Returns (count_imported, status_message).
    """
    try:
        if feed.feed_type == FeedType.CSV_URL.value:
            return await _fetch_csv_feed(feed)
        elif feed.feed_type == FeedType.JSON_URL.value:
            return await _fetch_json_feed(feed)
        elif feed.feed_type == FeedType.MANUAL.value:
            return 0, "Manual feed - no auto-fetch"
        else:
            return 0, f"Unsupported feed type: {feed.feed_type}"
    except Exception as e:
        logger.error(f"Error fetching feed '{feed.name}': {e}")
        return 0, f"Error: {str(e)[:200]}"


async def _fetch_csv_feed(feed: ThreatFeed) -> Tuple[int, str]:
    """Fetch IOCs from a CSV/text URL feed."""
    if not feed.url:
        return 0, "No URL configured"

    config = feed.parser_config or {}
    value_column = config.get("value_column", 0)
    comment_char = config.get("comment_char", "#")
    skip_header = config.get("skip_header", False)
    delimiter = config.get("delimiter", ",")
    ioc_type = config.get("ioc_type", "ip")

    headers = {}
    if feed.auth_config:
        if feed.auth_config.get("api_key_header"):
            headers[feed.auth_config["api_key_header"]] = feed.auth_config.get("api_key", "")
        if feed.auth_config.get("headers"):
            headers.update(feed.auth_config["headers"])

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        resp = await client.get(feed.url, headers=headers)
        resp.raise_for_status()
        text = resp.text

    iocs_to_upsert = []
    lines = text.strip().split("\n")
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        if skip_header and i == 0:
            continue

        parts = line.split(delimiter)
        if len(parts) <= value_column:
            continue

        value = parts[value_column].strip().strip('"').strip("'")
        if not value:
            continue

        # Auto-detect type if not specified
        detected_type = ioc_type
        if ioc_type == "auto":
            detected_type = _detect_ioc_type(value)
            if not detected_type:
                continue

        description = parts[1].strip() if len(parts) > 1 and value_column == 0 else None

        iocs_to_upsert.append({
            "ioc_type": detected_type,
            "value": value.lower() if detected_type.startswith("hash_") else value,
            "source": feed.name,
            "description": description,
            "threat_type": config.get("threat_type", "unknown"),
            "severity": config.get("severity", "medium"),
            "confidence": config.get("confidence", 60),
        })

    count = await _bulk_upsert_iocs(feed.id, iocs_to_upsert)
    return count, f"Fetched {count} IOCs from {len(lines)} lines"


async def _fetch_json_feed(feed: ThreatFeed) -> Tuple[int, str]:
    """Fetch IOCs from a JSON URL feed."""
    if not feed.url:
        return 0, "No URL configured"

    config = feed.parser_config or {}
    items_path = config.get("path", "")
    value_field = config.get("value_field", "value")
    type_field = config.get("type_field", "type")
    ioc_type = config.get("ioc_type", "ip")

    headers = {"Accept": "application/json"}
    if feed.auth_config:
        if feed.auth_config.get("api_key_header"):
            headers[feed.auth_config["api_key_header"]] = feed.auth_config.get("api_key", "")
        if feed.auth_config.get("headers"):
            headers.update(feed.auth_config["headers"])

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        resp = await client.get(feed.url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    # Navigate to items path
    items = data
    if items_path:
        for key in items_path.split("."):
            if isinstance(items, dict):
                items = items.get(key, [])
            elif isinstance(items, list) and key.isdigit():
                items = items[int(key)]

    if not isinstance(items, list):
        items = [items]

    iocs_to_upsert = []
    for item in items:
        if isinstance(item, str):
            value = item.strip()
            detected_type = ioc_type if ioc_type != "auto" else (_detect_ioc_type(value) or "ip")
            iocs_to_upsert.append({
                "ioc_type": detected_type,
                "value": value.lower() if detected_type.startswith("hash_") else value,
                "source": feed.name,
                "threat_type": config.get("threat_type", "unknown"),
                "severity": config.get("severity", "medium"),
                "confidence": config.get("confidence", 60),
            })
        elif isinstance(item, dict):
            value = str(item.get(value_field, "")).strip()
            if not value:
                continue
            item_type = item.get(type_field, ioc_type)
            # Normalize type
            if item_type in ("ip", "ipv4", "IPv4"):
                item_type = "ip"
            elif item_type in ("domain", "hostname", "fqdn"):
                item_type = "domain"
            elif item_type in ("url", "uri"):
                item_type = "url"
            elif item_type in ("md5", "hash_md5"):
                item_type = "hash_md5"
            elif item_type in ("sha1", "hash_sha1"):
                item_type = "hash_sha1"
            elif item_type in ("sha256", "hash_sha256"):
                item_type = "hash_sha256"
            else:
                item_type = ioc_type

            iocs_to_upsert.append({
                "ioc_type": item_type,
                "value": value.lower() if item_type.startswith("hash_") else value,
                "source": feed.name,
                "description": item.get("description") or item.get("info"),
                "threat_type": item.get("threat_type") or config.get("threat_type", "unknown"),
                "severity": item.get("severity") or config.get("severity", "medium"),
                "confidence": item.get("confidence") or config.get("confidence", 60),
                "tags": item.get("tags"),
            })

    count = await _bulk_upsert_iocs(feed.id, iocs_to_upsert)
    return count, f"Fetched {count} IOCs from {len(items)} items"


def _detect_ioc_type(value: str) -> Optional[str]:
    """Auto-detect the IOC type from its value."""
    value = value.strip()

    # IP address
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    # CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass

    # Hash detection by length
    if all(c in "0123456789abcdefABCDEF" for c in value):
        if len(value) == 32:
            return "hash_md5"
        elif len(value) == 40:
            return "hash_sha1"
        elif len(value) == 64:
            return "hash_sha256"

    # URL
    if value.startswith(("http://", "https://")):
        return "url"

    # Domain (basic heuristic)
    if "." in value and not value.startswith("/") and " " not in value:
        parts = value.split(".")
        if len(parts) >= 2 and all(p.replace("-", "").replace("_", "").isalnum() for p in parts):
            return "domain"

    return None


async def _bulk_upsert_iocs(feed_id: int, iocs: List[dict]) -> int:
    """Insert or update IOCs in bulk. Returns count of inserted/updated."""
    if not iocs:
        return 0

    count = 0
    async with async_session_maker() as session:
        try:
            now = datetime.now(timezone.utc)
            for ioc_data in iocs:
                # Check if exists
                result = await session.execute(
                    select(IOC).where(
                        IOC.ioc_type == ioc_data["ioc_type"],
                        IOC.value == ioc_data["value"]
                    )
                )
                existing = result.scalar_one_or_none()

                if existing:
                    # Update last_seen
                    existing.last_seen = now
                    existing.is_active = True
                    if ioc_data.get("severity"):
                        existing.severity = ioc_data["severity"]
                    if ioc_data.get("confidence"):
                        existing.confidence = int(ioc_data["confidence"])
                else:
                    ioc = IOC(
                        feed_id=feed_id,
                        ioc_type=ioc_data["ioc_type"],
                        value=ioc_data["value"],
                        severity=ioc_data.get("severity", "medium"),
                        confidence=int(ioc_data.get("confidence", 50)),
                        threat_type=ioc_data.get("threat_type"),
                        description=ioc_data.get("description"),
                        tags=ioc_data.get("tags"),
                        source=ioc_data.get("source"),
                        first_seen=now,
                        last_seen=now,
                        is_active=True,
                    )
                    session.add(ioc)
                    count += 1

            await session.commit()

            # Update feed IOC count
            result = await session.execute(
                select(func.count(IOC.id)).where(IOC.feed_id == feed_id, IOC.is_active == True)
            )
            ioc_count = result.scalar() or 0
            await session.execute(
                update(ThreatFeed).where(ThreatFeed.id == feed_id).values(ioc_count=ioc_count)
            )
            await session.commit()

        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to bulk upsert IOCs: {e}")

    return count


# ============ Feed Management ============

async def update_all_feeds():
    """Fetch updates for all enabled feeds that are due."""
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                select(ThreatFeed).where(ThreatFeed.is_enabled == True)
            )
            feeds = result.scalars().all()

            for feed in feeds:
                if feed.feed_type == FeedType.MANUAL.value:
                    continue

                # Check if update is due
                if feed.last_fetched_at:
                    next_fetch = feed.last_fetched_at + timedelta(minutes=feed.update_interval_minutes)
                    if datetime.now(timezone.utc) < next_fetch:
                        continue

                logger.info(f"Fetching threat feed: {feed.name}")
                count, message = await fetch_feed(feed)

                # Update feed status
                feed.last_fetched_at = datetime.now(timezone.utc)
                feed.last_fetch_status = "success" if count >= 0 else "error"
                feed.last_fetch_message = message
                await session.commit()

                logger.info(f"Feed '{feed.name}': {message}")

        except Exception as e:
            logger.error(f"Error updating feeds: {e}")


async def get_all_active_iocs() -> Dict[str, List[dict]]:
    """Get all active IOCs grouped by type for the matcher cache."""
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                select(IOC).where(IOC.is_active == True)
            )
            iocs = result.scalars().all()

            grouped = {"ip": [], "domain": [], "url": [],
                       "hash_md5": [], "hash_sha1": [], "hash_sha256": []}
            now = datetime.now(timezone.utc)

            for ioc in iocs:
                if ioc.expires_at and now > ioc.expires_at:
                    continue
                entry = {
                    "id": ioc.id,
                    "value": ioc.value,
                    "ioc_type": ioc.ioc_type,
                    "severity": ioc.severity,
                    "confidence": ioc.confidence,
                    "threat_type": ioc.threat_type or "unknown",
                    "feed_id": ioc.feed_id,
                    "source": ioc.source or "",
                }
                if ioc.ioc_type in grouped:
                    grouped[ioc.ioc_type].append(entry)

            return grouped
        except Exception as e:
            logger.error(f"Failed to load IOCs: {e}")
            return {"ip": [], "domain": [], "url": [],
                    "hash_md5": [], "hash_sha1": [], "hash_sha256": []}


# ============ Pre-Built Feeds ============

BUILTIN_FEEDS = [
    {
        "name": "Feodo Tracker - Botnet C2 IPs",
        "feed_type": "csv_url",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "ioc_types": ["ip"],
        "parser_config": {
            "value_column": 0,
            "comment_char": "#",
            "skip_header": False,
            "delimiter": ",",
            "ioc_type": "ip",
            "threat_type": "c2",
            "severity": "high",
            "confidence": 85,
        },
        "update_interval_minutes": 60,
    },
    {
        "name": "URLhaus - Malicious URLs",
        "feed_type": "csv_url",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "ioc_types": ["url"],
        "parser_config": {
            "value_column": 0,
            "comment_char": "#",
            "skip_header": False,
            "delimiter": ",",
            "ioc_type": "url",
            "threat_type": "malware",
            "severity": "high",
            "confidence": 80,
        },
        "update_interval_minutes": 60,
    },
    {
        "name": "MalwareBazaar - Recent MD5 Hashes",
        "feed_type": "csv_url",
        "url": "https://bazaar.abuse.ch/export/txt/md5/recent/",
        "ioc_types": ["hash_md5"],
        "parser_config": {
            "value_column": 0,
            "comment_char": "#",
            "skip_header": False,
            "delimiter": ",",
            "ioc_type": "hash_md5",
            "threat_type": "malware",
            "severity": "high",
            "confidence": 90,
        },
        "update_interval_minutes": 120,
    },
    {
        "name": "MalwareBazaar - Recent SHA256 Hashes",
        "feed_type": "csv_url",
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "ioc_types": ["hash_sha256"],
        "parser_config": {
            "value_column": 0,
            "comment_char": "#",
            "skip_header": False,
            "delimiter": ",",
            "ioc_type": "hash_sha256",
            "threat_type": "malware",
            "severity": "high",
            "confidence": 90,
        },
        "update_interval_minutes": 120,
    },
    {
        "name": "Emerging Threats - Compromised IPs",
        "feed_type": "csv_url",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ioc_types": ["ip"],
        "parser_config": {
            "value_column": 0,
            "comment_char": "#",
            "skip_header": False,
            "delimiter": "\t",
            "ioc_type": "ip",
            "threat_type": "scanner",
            "severity": "medium",
            "confidence": 70,
        },
        "update_interval_minutes": 360,
    },
]


async def seed_builtin_feeds():
    """Create built-in threat feeds if they don't already exist."""
    async with async_session_maker() as session:
        try:
            result = await session.execute(select(ThreatFeed.name))
            existing_names = {row[0] for row in result.all()}

            count = 0
            for feed_data in BUILTIN_FEEDS:
                if feed_data["name"] in existing_names:
                    continue

                feed = ThreatFeed(
                    name=feed_data["name"],
                    feed_type=feed_data["feed_type"],
                    url=feed_data.get("url"),
                    ioc_types=feed_data.get("ioc_types"),
                    parser_config=feed_data.get("parser_config"),
                    update_interval_minutes=feed_data.get("update_interval_minutes", 60),
                    is_enabled=True,
                )
                session.add(feed)
                count += 1

            if count > 0:
                await session.commit()
                logger.info(f"Seeded {count} built-in threat feeds")
            else:
                logger.debug("All built-in threat feeds already exist")

        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to seed threat feeds: {e}")
