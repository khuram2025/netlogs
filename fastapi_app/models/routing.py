"""
RoutingTable model - Store routing tables fetched from devices.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class RouteType:
    """Route type constants based on Fortinet output codes."""
    KERNEL = "K"       # Kernel route
    CONNECTED = "C"    # Directly connected
    STATIC = "S"       # Static route
    RIP = "R"          # RIP
    BGP = "B"          # BGP
    OSPF = "O"         # OSPF
    OSPF_IA = "IA"     # OSPF inter area
    OSPF_N1 = "N1"     # OSPF NSSA external type 1
    OSPF_N2 = "N2"     # OSPF NSSA external type 2
    OSPF_E1 = "E1"     # OSPF external type 1
    OSPF_E2 = "E2"     # OSPF external type 2
    ISIS = "i"         # IS-IS
    ISIS_L1 = "L1"     # IS-IS level-1
    ISIS_L2 = "L2"     # IS-IS level-2
    ISIS_IA = "ia"     # IS-IS inter area
    BGP_VPNV4 = "V"    # BGP VPNv4

    CHOICES = [
        (KERNEL, "Kernel"),
        (CONNECTED, "Connected"),
        (STATIC, "Static"),
        (RIP, "RIP"),
        (BGP, "BGP"),
        (OSPF, "OSPF"),
        (OSPF_IA, "OSPF Inter Area"),
        (OSPF_N1, "OSPF NSSA Type 1"),
        (OSPF_N2, "OSPF NSSA Type 2"),
        (OSPF_E1, "OSPF External Type 1"),
        (OSPF_E2, "OSPF External Type 2"),
        (ISIS, "IS-IS"),
        (ISIS_L1, "IS-IS Level 1"),
        (ISIS_L2, "IS-IS Level 2"),
        (ISIS_IA, "IS-IS Inter Area"),
        (BGP_VPNV4, "BGP VPNv4"),
    ]


class RoutingTableSnapshot(Base):
    """Snapshot of a device's routing table at a point in time."""

    __tablename__ = "routing_table_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Fortinet VDOM name
    vrf: Mapped[str] = mapped_column(String(50), default="0", nullable=False)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    route_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    fetch_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_snapshot_device", "device_id"),
        Index("idx_snapshot_fetched", "fetched_at"),
        Index("idx_snapshot_device_time", "device_id", "fetched_at"),
        Index("idx_snapshot_vdom", "vdom"),
        Index("idx_snapshot_device_vdom", "device_id", "vdom"),
    )

    def __repr__(self) -> str:
        return f"<RoutingTableSnapshot device:{self.device_id} @ {self.fetched_at}>"


class RoutingEntry(Base):
    """Individual routing table entry."""

    __tablename__ = "routing_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("routing_table_snapshots.id", ondelete="CASCADE"), nullable=False
    )

    # Route details
    route_type: Mapped[str] = mapped_column(String(10), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    network: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "10.0.0.0/8"
    prefix_length: Mapped[int] = mapped_column(Integer, nullable=False)  # e.g., 8

    # Next hop info
    next_hop: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    interface: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    tunnel_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Metrics
    admin_distance: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metric: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    preference: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # e.g., "[1/0]"

    # Additional info
    age: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., "01w3d22h"
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Fortinet VDOM name
    vrf: Mapped[str] = mapped_column(String(50), default="0", nullable=False)
    is_recursive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recursive_via: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Metadata
    raw_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_route_device", "device_id"),
        Index("idx_route_snapshot", "snapshot_id"),
        Index("idx_route_network", "network"),
        Index("idx_route_type", "route_type"),
        Index("idx_route_next_hop", "next_hop"),
        Index("idx_route_interface", "interface"),
        Index("idx_route_device_network", "device_id", "network"),
    )

    def __repr__(self) -> str:
        return f"<RoutingEntry {self.route_type} {self.network} via {self.next_hop}>"

    @property
    def route_type_display(self) -> str:
        """Return human-readable route type."""
        for value, display in RouteType.CHOICES:
            if value == self.route_type:
                return display
        return self.route_type

    @property
    def is_directly_connected(self) -> bool:
        """Check if route is directly connected."""
        return self.route_type == RouteType.CONNECTED

    @property
    def cidr(self) -> str:
        """Return network in CIDR notation."""
        return f"{self.network}"


class RouteChange(Base):
    """Track changes in routing tables between snapshots."""

    __tablename__ = "route_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("routing_table_snapshots.id", ondelete="CASCADE"), nullable=False
    )

    change_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ADDED, REMOVED, MODIFIED
    network: Mapped[str] = mapped_column(String(50), nullable=False)

    # Old values (for REMOVED or MODIFIED)
    old_route_type: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    old_next_hop: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    old_interface: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # New values (for ADDED or MODIFIED)
    new_route_type: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    new_next_hop: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    new_interface: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_change_device", "device_id"),
        Index("idx_change_snapshot", "snapshot_id"),
        Index("idx_change_type", "change_type"),
        Index("idx_change_network", "network"),
        Index("idx_change_detected", "detected_at"),
    )

    def __repr__(self) -> str:
        return f"<RouteChange {self.change_type} {self.network}>"


class ChangeType:
    """Change type constants."""
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
