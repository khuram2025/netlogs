"""
Threat Intelligence models - feeds, IOCs, and correlation rules.
"""

from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, Float,
    ForeignKey, UniqueConstraint, JSON, Index
)
from sqlalchemy.orm import relationship

from ..db.database import Base


class FeedType(str, Enum):
    CSV_URL = "csv_url"
    JSON_URL = "json_url"
    STIX_TAXII = "stix_taxii"
    MANUAL = "manual"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class IOCSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatFeed(Base):
    """Threat intelligence feed source configuration."""
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, unique=True)
    feed_type = Column(String(30), nullable=False)  # csv_url, json_url, stix_taxii, manual
    url = Column(String(500), nullable=True)
    auth_config = Column(JSON, nullable=True)  # API keys, tokens, headers
    ioc_types = Column(JSON, nullable=True)  # List of IOC types this feed provides

    # Parsing configuration
    parser_config = Column(JSON, nullable=True)
    # For CSV: {"value_column": 0, "type_column": 1, "skip_header": true, "comment_char": "#", "delimiter": ","}
    # For JSON: {"path": "data.items", "value_field": "indicator", "type_field": "type"}

    update_interval_minutes = Column(Integer, default=60)
    is_enabled = Column(Boolean, default=True)

    # Status
    last_fetched_at = Column(DateTime(timezone=True), nullable=True)
    last_fetch_status = Column(String(20), nullable=True)  # success, error, pending
    last_fetch_message = Column(Text, nullable=True)
    ioc_count = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    iocs = relationship("IOC", back_populates="feed", cascade="all, delete-orphan")


class IOC(Base):
    """Individual Indicator of Compromise."""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=True)
    ioc_type = Column(String(20), nullable=False, index=True)  # ip, domain, url, hash_md5, hash_sha1, hash_sha256
    value = Column(String(500), nullable=False, index=True)
    severity = Column(String(20), default="medium")  # critical, high, medium, low
    confidence = Column(Integer, default=50)  # 0-100
    threat_type = Column(String(100), nullable=True)  # malware, c2, phishing, scanner, botnet, tor_exit
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # List of tag strings

    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(200), nullable=True)

    is_active = Column(Boolean, default=True, index=True)
    match_count = Column(Integer, default=0)
    last_matched_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    feed = relationship("ThreatFeed", back_populates="iocs")

    # Unique constraint on type + value
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_ioc_active_type", "is_active", "ioc_type"),
    )

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_effective(self):
        return self.is_active and not self.is_expired
