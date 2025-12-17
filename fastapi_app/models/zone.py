"""
FortiGate Zone model - Store zone/interface/subnet mappings from Fortinet devices.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class ZoneSnapshot(Base):
    """Snapshot of zone/interface data fetched from a Fortinet device."""

    __tablename__ = "zone_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_zone_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_interface_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    zone_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    interface_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    fetch_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_zone_snapshot_device", "device_id"),
        Index("idx_zone_snapshot_fetched", "fetched_at"),
        Index("idx_zone_snapshot_device_vdom", "device_id", "vdom"),
    )

    def __repr__(self) -> str:
        return f"<ZoneSnapshot device:{self.device_id} @ {self.fetched_at}>"


class ZoneEntry(Base):
    """Zone configuration entry - maps zone to its member interfaces."""

    __tablename__ = "zone_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("zone_snapshots.id", ondelete="CASCADE"), nullable=False
    )

    # Zone details
    zone_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    intrazone: Mapped[str] = mapped_column(String(20), default="deny", nullable=False)  # allow or deny

    # Member interfaces stored as JSON array
    interfaces: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # ["VLAN101", "VLAN102"]

    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_zone_device", "device_id"),
        Index("idx_zone_snapshot", "snapshot_id"),
        Index("idx_zone_name", "zone_name"),
        Index("idx_zone_device_vdom", "device_id", "vdom"),
    )

    def __repr__(self) -> str:
        return f"<ZoneEntry {self.zone_name}>"


class InterfaceEntry(Base):
    """Interface configuration entry with IP/subnet information."""

    __tablename__ = "interface_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("zone_snapshots.id", ondelete="CASCADE"), nullable=False
    )

    # Interface details
    interface_name: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    subnet_mask: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    subnet_cidr: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., "10.10.101.0/24"

    # Interface type and status
    interface_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # vlan, physical, aggregate, tunnel
    addressing_mode: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # static, dhcp, pppoe
    status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)  # up, down

    # Associated zone (if any)
    zone_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_interface_device", "device_id"),
        Index("idx_interface_snapshot", "snapshot_id"),
        Index("idx_interface_name", "interface_name"),
        Index("idx_interface_zone", "zone_name"),
        Index("idx_interface_device_vdom", "device_id", "vdom"),
        Index("idx_interface_subnet", "subnet_cidr"),
    )

    def __repr__(self) -> str:
        return f"<InterfaceEntry {self.interface_name} {self.ip_address}>"
