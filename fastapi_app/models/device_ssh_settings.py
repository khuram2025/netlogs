"""
Device SSH settings - optional per-device SSH target override.

Use-case: syslog may come from one interface/IP, while SSH management is reachable
via a different interface/IP. This table lets you keep `devices_device.ip_address`
for log attribution while using a separate SSH host for routing table collection.
"""

from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class DeviceSshSettings(Base):
    """Optional SSH connection settings for a device."""

    __tablename__ = "device_ssh_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("devices_device.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    ssh_host: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_device_ssh_settings_device", "device_id"),
        Index("idx_device_ssh_settings_host", "ssh_host"),
    )

    def __repr__(self) -> str:
        return f"<DeviceSshSettings device:{self.device_id} host:{self.ssh_host}>"

