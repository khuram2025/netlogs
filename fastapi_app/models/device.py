"""
Device model - SQLAlchemy equivalent of Django Device model.
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import String, Integer, BigInteger, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class DeviceStatus:
    """Device status constants."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

    CHOICES = [
        (PENDING, "Pending"),
        (APPROVED, "Approved"),
        (REJECTED, "Rejected"),
    ]


class ParserType:
    """Parser type constants."""
    GENERIC = "GENERIC"
    FORTINET = "FORTINET"
    PALOALTO = "PALOALTO"

    CHOICES = [
        (GENERIC, "Generic Syslog"),
        (FORTINET, "Fortinet"),
        (PALOALTO, "Palo Alto"),
    ]


class RetentionDays:
    """Retention days options."""
    CHOICES = [
        (7, "7 days"),
        (14, "14 days"),
        (30, "30 days"),
        (60, "60 days"),
        (90, "90 days (default)"),
        (180, "180 days"),
        (365, "1 year"),
        (0, "Forever (no auto-delete)"),
    ]


class Device(Base):
    """Device model for tracking firewall/syslog sources."""

    __tablename__ = "devices_device"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default=DeviceStatus.PENDING, nullable=False
    )
    parser: Mapped[str] = mapped_column(
        String(50), default=ParserType.GENERIC, nullable=False
    )
    device_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_log_received: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    log_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    __table_args__ = (
        Index("idx_device_status", "status"),
        Index("idx_device_ip", "ip_address"),
        Index("idx_device_last_log", "last_log_received"),
        Index("idx_device_status_parser", "status", "parser"),
    )

    def __repr__(self) -> str:
        return f"<Device {self.ip_address} ({self.status})>"

    @property
    def is_stale(self) -> bool:
        """Returns True if no logs received in the last 5 minutes."""
        if not self.last_log_received:
            return False
        return datetime.now(self.last_log_received.tzinfo) - self.last_log_received > timedelta(minutes=5)

    @property
    def status_display(self) -> str:
        """Return human-readable status."""
        for value, display in DeviceStatus.CHOICES:
            if value == self.status:
                return display
        return self.status

    @property
    def parser_display(self) -> str:
        """Return human-readable parser name."""
        for value, display in ParserType.CHOICES:
            if value == self.parser:
                return display
        return self.parser

    @property
    def retention_display(self) -> str:
        """Return human-readable retention period."""
        for value, display in RetentionDays.CHOICES:
            if value == self.retention_days:
                return display
        return f"{self.retention_days} days"
