"""
Routing Service - Orchestrates routing table collection and storage.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, List, Dict, Tuple

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device, ParserType
from ..models.credential import DeviceCredential, DeviceVdom
from ..models.device_ssh_settings import DeviceSshSettings
from ..models.routing import (
    RoutingTableSnapshot, RoutingEntry, RouteChange, ChangeType
)
from .ssh_service import SSHService
from .routing_parser import RoutingTableParser, ParsedRoute

logger = logging.getLogger(__name__)


def _scrub_for_pg_text(s):
    """Strip characters Postgres TEXT cannot store.

    Postgres rejects strings containing the NUL byte (0x00) — common in raw
    SSH/terminal output — with `CharacterNotInRepertoireError`. Also drop the
    other C0 control characters except CR/LF/TAB which are legitimate."""
    if s is None:
        return None
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return None
    # Remove NUL and other forbidden control bytes; keep \t \n \r.
    return s.translate({i: None for i in range(0x20) if i not in (0x09, 0x0A, 0x0D)})


class RoutingService:
    """Service for collecting and managing routing tables."""

    @classmethod
    async def fetch_routing_table(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession,
        vdom: Optional[str] = None
    ) -> Tuple[bool, str, Optional[RoutingTableSnapshot]]:
        """
        Fetch routing table from device and store in database.
        Returns (success, message, snapshot).

        Args:
            device: The device to fetch from
            credential: SSH credentials
            db: Database session
            vdom: Optional VDOM name for Fortinet devices
        """
        vdom_display = f" (VDOM: {vdom})" if vdom else ""
        # device.ip_address is a Postgres INET → IPv4Address; coerce to str
        # so paramiko/socket.getaddrinfo accept it.
        ssh_host = str(device.ip_address)
        ssh_host_result = await db.execute(
            select(DeviceSshSettings.ssh_host)
            .where(DeviceSshSettings.device_id == device.id)
            .limit(1)
        )
        ssh_host_override = ssh_host_result.scalar_one_or_none()
        if ssh_host_override:
            override = str(ssh_host_override).strip()
            if override:
                ssh_host = override

        ssh_display = ssh_host if ssh_host != str(device.ip_address) else device.ip_address
        logger.info(f"Fetching routing table for device {device.ip_address} via {ssh_display}{vdom_display}")

        # Get routing table via SSH (vendor-aware)
        if device.parser == ParserType.FORTINET:
            result = await asyncio.to_thread(
                SSHService.get_fortinet_routing_table,
                host=str(ssh_host),
                username=credential.username,
                password=credential.password,
                port=credential.port,
                vdom=vdom,
            )
        elif device.parser == ParserType.PALOALTO:
            # PAN-OS calls them "virtual routers"; reuse the vdom slot in the
            # request signature so existing per-VR fetch code paths still work.
            result = await asyncio.to_thread(
                SSHService.get_paloalto_routing_table,
                host=str(ssh_host),
                username=credential.username,
                password=credential.password,
                port=credential.port,
                virtual_router=vdom,
            )
        else:
            return False, f"Unsupported device type: {device.parser}", None

        # Update credential last_used
        credential.last_used = datetime.utcnow()

        if not result.success:
            # Create failed snapshot record
            snapshot = RoutingTableSnapshot(
                device_id=device.id,
                vdom=vdom,
                raw_output=_scrub_for_pg_text(result.output) or "",
                route_count=0,
                success=False,
                error_message=_scrub_for_pg_text(result.error),
                fetch_duration_ms=result.duration_ms
            )
            db.add(snapshot)
            await db.commit()
            return False, result.error or "Unknown error", snapshot

        # Update credential last_success
        credential.last_success = datetime.utcnow()

        # Parse the routing table
        routes = RoutingTableParser.parse(result.output, device.parser)

        # Create snapshot. raw_output goes through _scrub_for_pg_text because
        # terminal capture often contains NUL/control bytes that Postgres TEXT
        # rejects (CharacterNotInRepertoireError).
        snapshot = RoutingTableSnapshot(
            device_id=device.id,
            vdom=vdom,
            raw_output=_scrub_for_pg_text(result.output),
            route_count=len(routes),
            success=True,
            fetch_duration_ms=result.duration_ms
        )
        db.add(snapshot)
        await db.flush()  # Get snapshot ID

        # Store individual routes
        for parsed_route in routes:
            entry = RoutingEntry(
                device_id=device.id,
                snapshot_id=snapshot.id,
                route_type=parsed_route.route_type,
                is_default=parsed_route.is_default,
                network=parsed_route.network,
                prefix_length=parsed_route.prefix_length,
                next_hop=parsed_route.next_hop,
                interface=parsed_route.interface,
                tunnel_name=parsed_route.tunnel_name,
                admin_distance=parsed_route.admin_distance,
                metric=parsed_route.metric,
                preference=parsed_route.preference,
                age=parsed_route.age,
                vdom=vdom,
                vrf=parsed_route.vrf,
                is_recursive=parsed_route.is_recursive,
                recursive_via=parsed_route.recursive_via,
                raw_line=_scrub_for_pg_text(parsed_route.raw_line),
            )
            db.add(entry)

        # Detect and record changes from previous snapshot
        await cls._detect_changes(device.id, snapshot.id, routes, db)

        await db.commit()
        await db.refresh(snapshot)

        logger.info(f"Successfully fetched {len(routes)} routes from {device.ip_address}")
        return True, f"Fetched {len(routes)} routes", snapshot

    @classmethod
    async def _detect_changes(
        cls,
        device_id: int,
        new_snapshot_id: int,
        new_routes: List[ParsedRoute],
        db: AsyncSession
    ):
        """Detect and record changes between current and previous snapshot."""
        # Get previous snapshot
        prev_snapshot_result = await db.execute(
            select(RoutingTableSnapshot)
            .where(
                and_(
                    RoutingTableSnapshot.device_id == device_id,
                    RoutingTableSnapshot.success == True,
                    RoutingTableSnapshot.id != new_snapshot_id
                )
            )
            .order_by(desc(RoutingTableSnapshot.fetched_at))
            .limit(1)
        )
        prev_snapshot = prev_snapshot_result.scalar_one_or_none()

        if not prev_snapshot:
            logger.info("No previous snapshot found, skipping change detection")
            return

        # Get previous routes
        prev_routes_result = await db.execute(
            select(RoutingEntry)
            .where(RoutingEntry.snapshot_id == prev_snapshot.id)
        )
        prev_routes = prev_routes_result.scalars().all()

        # Build lookup maps
        prev_route_map = {}
        for r in prev_routes:
            key = (r.network, r.next_hop or '', r.interface or '')
            prev_route_map[key] = r

        new_route_map = {}
        for r in new_routes:
            key = (r.network, r.next_hop or '', r.interface or '')
            new_route_map[key] = r

        # Find added routes
        for key, route in new_route_map.items():
            if key not in prev_route_map:
                # Check if network exists with different next_hop
                network_existed = any(
                    pk[0] == key[0] for pk in prev_route_map.keys()
                )
                change_type = ChangeType.MODIFIED if network_existed else ChangeType.ADDED

                # Find old route if modified
                old_route = None
                if network_existed:
                    for pk, pr in prev_route_map.items():
                        if pk[0] == key[0]:
                            old_route = pr
                            break

                change = RouteChange(
                    device_id=device_id,
                    snapshot_id=new_snapshot_id,
                    change_type=change_type,
                    network=route.network,
                    new_route_type=route.route_type,
                    new_next_hop=route.next_hop,
                    new_interface=route.interface,
                    old_route_type=old_route.route_type if old_route else None,
                    old_next_hop=old_route.next_hop if old_route else None,
                    old_interface=old_route.interface if old_route else None,
                )
                db.add(change)

        # Find removed routes
        for key, route in prev_route_map.items():
            if key not in new_route_map:
                # Check if network still exists with different path
                network_exists = any(
                    nk[0] == key[0] for nk in new_route_map.keys()
                )
                if not network_exists:
                    # Route completely removed
                    change = RouteChange(
                        device_id=device_id,
                        snapshot_id=new_snapshot_id,
                        change_type=ChangeType.REMOVED,
                        network=route.network,
                        old_route_type=route.route_type,
                        old_next_hop=route.next_hop,
                        old_interface=route.interface,
                    )
                    db.add(change)

    @classmethod
    async def get_latest_routes(
        cls,
        device_id: int,
        db: AsyncSession
    ) -> Tuple[Optional[RoutingTableSnapshot], List[RoutingEntry]]:
        """Get the latest routing table for a device."""
        # Get latest successful snapshot
        snapshot_result = await db.execute(
            select(RoutingTableSnapshot)
            .where(
                and_(
                    RoutingTableSnapshot.device_id == device_id,
                    RoutingTableSnapshot.success == True
                )
            )
            .order_by(desc(RoutingTableSnapshot.fetched_at))
            .limit(1)
        )
        snapshot = snapshot_result.scalar_one_or_none()

        if not snapshot:
            return None, []

        # Get routes for this snapshot
        routes_result = await db.execute(
            select(RoutingEntry)
            .where(RoutingEntry.snapshot_id == snapshot.id)
            .order_by(RoutingEntry.network)
        )
        routes = routes_result.scalars().all()

        return snapshot, routes

    @classmethod
    async def get_route_changes(
        cls,
        device_id: int,
        db: AsyncSession,
        limit: int = 100
    ) -> List[RouteChange]:
        """Get recent route changes for a device."""
        result = await db.execute(
            select(RouteChange)
            .where(RouteChange.device_id == device_id)
            .order_by(desc(RouteChange.detected_at))
            .limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def get_snapshots(
        cls,
        device_id: int,
        db: AsyncSession,
        limit: int = 50
    ) -> List[RoutingTableSnapshot]:
        """Get routing table snapshots for a device."""
        result = await db.execute(
            select(RoutingTableSnapshot)
            .where(RoutingTableSnapshot.device_id == device_id)
            .order_by(desc(RoutingTableSnapshot.fetched_at))
            .limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def get_fortinet_devices_with_credentials(
        cls,
        db: AsyncSession
    ) -> List[Tuple[Device, DeviceCredential]]:
        """Get all Fortinet devices that have SSH credentials configured."""
        result = await db.execute(
            select(Device, DeviceCredential)
            .join(DeviceCredential, Device.id == DeviceCredential.device_id)
            .where(
                and_(
                    Device.parser == ParserType.FORTINET,
                    Device.status == 'APPROVED',
                    DeviceCredential.is_active == True,
                    DeviceCredential.credential_type == 'SSH'
                )
            )
        )
        return result.all()

    @classmethod
    async def get_device_vdoms(
        cls,
        device_id: int,
        db: AsyncSession
    ) -> List[DeviceVdom]:
        """Get all active VDOMs configured for a device."""
        result = await db.execute(
            select(DeviceVdom)
            .where(
                and_(
                    DeviceVdom.device_id == device_id,
                    DeviceVdom.is_active == True
                )
            )
            .order_by(DeviceVdom.is_default.desc(), DeviceVdom.vdom_name)
        )
        return result.scalars().all()

    @classmethod
    async def fetch_all_vdom_routing_tables(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession
    ) -> Dict[str, Tuple[bool, str, Optional[RoutingTableSnapshot]]]:
        """
        Fetch routing tables for all VDOMs configured on a device.
        Returns a dict mapping vdom_name to (success, message, snapshot).
        If no VDOMs are configured, fetches from global context (vdom=None).
        """
        results = {}

        # Get configured VDOMs
        vdoms = await cls.get_device_vdoms(device.id, db)

        if not vdoms:
            # No VDOMs configured, fetch from default/global context
            logger.info(f"No VDOMs configured for {device.ip_address}, fetching from global context")
            success, message, snapshot = await cls.fetch_routing_table(
                device, credential, db, vdom=None
            )
            results['global'] = (success, message, snapshot)
        else:
            # Fetch from each VDOM
            for vdom in vdoms:
                logger.info(f"Fetching routing table for {device.ip_address} VDOM: {vdom.vdom_name}")
                success, message, snapshot = await cls.fetch_routing_table(
                    device, credential, db, vdom=vdom.vdom_name
                )
                results[vdom.vdom_name] = (success, message, snapshot)

        return results

    @classmethod
    async def get_latest_routes_by_vdom(
        cls,
        device_id: int,
        db: AsyncSession,
        vdom: Optional[str] = None
    ) -> Tuple[Optional[RoutingTableSnapshot], List[RoutingEntry]]:
        """Get the latest routing table for a device, optionally filtered by VDOM."""
        # Build query with optional VDOM filter
        conditions = [
            RoutingTableSnapshot.device_id == device_id,
            RoutingTableSnapshot.success == True
        ]

        if vdom is not None:
            conditions.append(RoutingTableSnapshot.vdom == vdom)

        snapshot_result = await db.execute(
            select(RoutingTableSnapshot)
            .where(and_(*conditions))
            .order_by(desc(RoutingTableSnapshot.fetched_at))
            .limit(1)
        )
        snapshot = snapshot_result.scalar_one_or_none()

        if not snapshot:
            return None, []

        # Get routes for this snapshot
        routes_result = await db.execute(
            select(RoutingEntry)
            .where(RoutingEntry.snapshot_id == snapshot.id)
            .order_by(RoutingEntry.network)
        )
        routes = routes_result.scalars().all()

        return snapshot, routes

    @classmethod
    async def get_available_vdoms(
        cls,
        device_id: int,
        db: AsyncSession
    ) -> List[str]:
        """Get list of VDOMs that have routing data for a device."""
        result = await db.execute(
            select(RoutingTableSnapshot.vdom)
            .where(
                and_(
                    RoutingTableSnapshot.device_id == device_id,
                    RoutingTableSnapshot.success == True
                )
            )
            .distinct()
            .order_by(RoutingTableSnapshot.vdom)
        )
        vdoms = [row[0] for row in result.all() if row[0] is not None]
        return vdoms
