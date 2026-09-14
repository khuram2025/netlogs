"""
Firewall policy / rule-base models.

Captures the *configured* security policy of a device — fetched periodically
via SSH/API — so Policy Lookup can simulate flow allowance offline (i.e.
without waiting for traffic to actually hit a rule and produce a syslog).
"""

from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    String, Integer, DateTime, ForeignKey, Text, Index, Boolean,
    JSON, BigInteger,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class FirewallPolicySnapshot(Base):
    """Snapshot of a device's full rule base + objects at a point in time.

    Mirrors the snapshot model used for routing / zones so the Fetch History
    UI works the same way for all three.
    """

    __tablename__ = "firewall_policy_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    policy_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    address_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    addrgrp_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    service_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    servicegrp_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    fetch_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_fwpolicy_snap_device", "device_id"),
        Index("idx_fwpolicy_snap_device_time", "device_id", "fetched_at"),
        Index("idx_fwpolicy_snap_vdom", "device_id", "vdom"),
    )

    def __repr__(self) -> str:
        return f"<FirewallPolicySnapshot device:{self.device_id} @ {self.fetched_at}>"


class FirewallPolicy(Base):
    """A single security policy / firewall rule.

    Vendor-agnostic shape: lists are stored as JSON arrays so the same
    schema fits Fortinet, Palo Alto, Cisco etc. The original vendor
    definition is preserved in `raw_definition` for audit/debug.
    """

    __tablename__ = "firewall_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("firewall_policy_snapshots.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Vendor-native rule identifier (e.g. FortiGate policyid integer, PAN rule name).
    rule_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    action: Mapped[str] = mapped_column(String(20), default="accept", nullable=False)

    # Zones / interfaces — lists of names.
    src_zones: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    dst_zones: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Address / service references — names that resolve via the address/service tables.
    src_addresses: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    dst_addresses: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    services: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    applications: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    users: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    nat_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    log_traffic: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    schedule: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Operational metrics if vendor exposes them.
    hit_count: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    raw_definition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_fwpolicy_device", "device_id"),
        Index("idx_fwpolicy_snapshot", "snapshot_id"),
        Index("idx_fwpolicy_device_vdom_pos", "device_id", "vdom", "position"),
        Index("idx_fwpolicy_action", "action"),
        Index("idx_fwpolicy_name", "name"),
    )

    def __repr__(self) -> str:
        return f"<FirewallPolicy {self.rule_id} {self.name} {self.action}>"


class FirewallAddressObject(Base):
    """Named address object (Fortinet `firewall address` / PAN `address`).

    `kind` is one of:  ipmask | iprange | fqdn | geography | dynamic | group
    For groups (kind='group'), `members` is the list of contained object names.
    """

    __tablename__ = "firewall_address_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("firewall_policy_snapshots.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), default="ipmask", nullable=False)
    value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    members: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_definition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_fwaddr_device", "device_id"),
        Index("idx_fwaddr_snapshot", "snapshot_id"),
        Index("idx_fwaddr_device_name", "device_id", "vdom", "name"),
        Index("idx_fwaddr_kind", "kind"),
    )

    def __repr__(self) -> str:
        return f"<FirewallAddressObject {self.name} ({self.kind})>"


class FirewallServiceObject(Base):
    """Named service object (Fortinet `firewall service custom`/`group`,
    PAN `service`/`service-group`).

    `protocol` is `tcp` | `udp` | `tcp_udp` | `icmp` | `ip` | `group`.
    `ports` is the textual port spec (e.g. ``"443"`` or ``"1024-65535"``).
    For groups, `members` is the list of contained object names.
    """

    __tablename__ = "firewall_service_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("firewall_policy_snapshots.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp", nullable=False)
    ports: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    members: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_definition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_fwsvc_device", "device_id"),
        Index("idx_fwsvc_snapshot", "snapshot_id"),
        Index("idx_fwsvc_device_name", "device_id", "vdom", "name"),
        Index("idx_fwsvc_protocol", "protocol"),
    )

    def __repr__(self) -> str:
        return f"<FirewallServiceObject {self.name} {self.protocol}/{self.ports}>"
