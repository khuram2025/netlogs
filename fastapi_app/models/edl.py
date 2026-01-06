"""External Dynamic List (EDL) models for firewall integration."""
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index, Enum as SQLEnum
from sqlalchemy.orm import relationship
from fastapi_app.db.database import Base


class EDLType(str, Enum):
    """Type of entries allowed in the list."""
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class EDLList(Base):
    """External Dynamic List container."""
    __tablename__ = "edl_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    list_type = Column(SQLEnum(EDLType), nullable=False, default=EDLType.IP)

    # Access control
    access_token = Column(String(64), nullable=True, index=True)  # Optional token for protected access
    is_active = Column(Boolean, default=True, index=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    entries = relationship("EDLEntry", back_populates="edl_list", cascade="all, delete-orphan", lazy="selectin")

    @property
    def entry_count(self):
        """Count of entries in this list."""
        return len(self.entries) if self.entries else 0

    @property
    def active_entry_count(self):
        """Count of active entries."""
        return sum(1 for e in self.entries if e.is_active) if self.entries else 0

    @property
    def type_display(self):
        """Human-readable type display."""
        return {
            EDLType.IP: "IP Address",
            EDLType.DOMAIN: "Domain",
            EDLType.URL: "URL",
            EDLType.HASH: "File Hash"
        }.get(self.list_type, self.list_type)

    @property
    def type_icon(self):
        """Icon for list type."""
        return {
            EDLType.IP: "🌐",
            EDLType.DOMAIN: "🔗",
            EDLType.URL: "📄",
            EDLType.HASH: "🔐"
        }.get(self.list_type, "📋")


class EDLEntry(Base):
    """Individual entry in an EDL list."""
    __tablename__ = "edl_entries"

    id = Column(Integer, primary_key=True, index=True)
    edl_list_id = Column(Integer, ForeignKey("edl_lists.id", ondelete="CASCADE"), nullable=False, index=True)

    # Entry data
    value = Column(String(2048), nullable=False)  # IP, domain, or URL
    description = Column(String(500), nullable=True)

    # Status
    is_active = Column(Boolean, default=True, index=True)

    # Expiration (optional)
    expires_at = Column(DateTime, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Source tracking (for imports)
    source = Column(String(100), nullable=True)  # manual, import, api

    # Relationships
    edl_list = relationship("EDLList", back_populates="entries")

    @property
    def is_expired(self):
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def is_effective(self):
        """Check if entry is currently active and not expired."""
        return self.is_active and not self.is_expired

    __table_args__ = (
        Index('ix_edl_entries_list_active', 'edl_list_id', 'is_active'),
        Index('ix_edl_entries_value', 'value'),
    )
