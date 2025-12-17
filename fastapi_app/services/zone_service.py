"""
Zone Service - Parse and store FortiGate zone/interface configuration.
"""

import asyncio
import logging
import re
import time
import ipaddress
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass

from sqlalchemy import select, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device
from ..models.credential import DeviceCredential, DeviceVdom
from ..models.zone import ZoneSnapshot, ZoneEntry, InterfaceEntry
from ..models.device_ssh_settings import DeviceSshSettings
from .ssh_service import SSHService

logger = logging.getLogger(__name__)


@dataclass
class ParsedZone:
    """Parsed zone data."""
    name: str
    description: Optional[str] = None
    intrazone: str = "deny"
    interfaces: List[str] = None

    def __post_init__(self):
        if self.interfaces is None:
            self.interfaces = []


@dataclass
class ParsedInterface:
    """Parsed interface data."""
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    subnet_cidr: Optional[str] = None
    interface_type: Optional[str] = None
    addressing_mode: Optional[str] = None
    status: str = "up"
    zone_name: Optional[str] = None
    vdom: Optional[str] = None  # VDOM this interface belongs to


class ZoneService:
    """Service for managing FortiGate zone/interface data."""

    @staticmethod
    def parse_zone_output(raw_output: str) -> List[ParsedZone]:
        """
        Parse FortiGate 'show system zone' output.

        Example output:
        config system zone
            edit "NET_MGMT"
                set description "Managment"
                set interface "VLAN101"
            next
            edit "USR_DATA"
                set interface "USR_B7GF_200" "VLAN202" "VLAN203"
            next
            edit "SRV_MGMT"
                set intrazone allow
                set interface "VLAN106" "VLAN180"
            next
        end
        """
        zones = []
        current_zone = None

        lines = raw_output.split('\n')

        for line in lines:
            line = line.strip()

            # Match zone name: edit "ZONE_NAME" or edit ZONE_NAME
            edit_match = re.match(r'edit\s+"?([^"]+)"?', line)
            if edit_match:
                if current_zone:
                    zones.append(current_zone)
                current_zone = ParsedZone(name=edit_match.group(1).strip())
                continue

            if current_zone:
                # Match description
                desc_match = re.match(r'set\s+description\s+"?([^"]*)"?', line)
                if desc_match:
                    current_zone.description = desc_match.group(1).strip()
                    continue

                # Match intrazone setting
                intra_match = re.match(r'set\s+intrazone\s+(\w+)', line)
                if intra_match:
                    current_zone.intrazone = intra_match.group(1).strip()
                    continue

                # Match interfaces - can be multiple quoted strings
                intf_match = re.match(r'set\s+interface\s+(.*)', line)
                if intf_match:
                    # Extract all quoted interface names
                    interfaces_str = intf_match.group(1)
                    interfaces = re.findall(r'"([^"]+)"', interfaces_str)
                    if not interfaces:
                        # Try unquoted
                        interfaces = interfaces_str.split()
                    current_zone.interfaces = interfaces
                    continue

                # End of zone block
                if line == 'next' or line == 'end':
                    if current_zone:
                        zones.append(current_zone)
                        current_zone = None

        # Add last zone if not added
        if current_zone and current_zone not in zones:
            zones.append(current_zone)

        return zones

    @staticmethod
    def parse_interface_output(raw_output: str, zones: List[ParsedZone] = None, target_vdom: Optional[str] = None) -> List[ParsedInterface]:
        """
        Parse FortiGate 'show system interface' output (config-style).

        Example output format:
        config system interface
            edit "port1"
                set vdom "root"
                set ip 192.168.1.1 255.255.255.0
                set type physical
                set status up
            next
            edit "VLAN101"
                set vdom "Campus"
                set ip 10.10.101.254 255.255.255.0
                set type vlan
                set vlanid 101
                set interface "port10"
            next
        end

        Also handles block-style output from 'get system interface':
        == [ interface_name ]
        name: xxx   mode: static   ip: x.x.x.x y.y.y.y   status: up   vdom: xxx   ...

        Args:
            raw_output: Raw SSH command output
            zones: List of parsed zones for zone lookup
            target_vdom: If specified, only return interfaces belonging to this VDOM
        """
        interfaces = []

        # Build zone lookup: interface_name -> zone_name
        zone_lookup = {}
        if zones:
            for zone in zones:
                for intf_name in zone.interfaces:
                    zone_lookup[intf_name] = zone.name

        lines = raw_output.split('\n')
        current_interface = None
        parsing_mode = None  # 'config' or 'block'

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Detect config-style format: edit "interface_name"
            edit_match = re.match(r'^edit\s+"?([^"]+)"?', line_stripped)
            if edit_match:
                parsing_mode = 'config'
                # Save previous interface if exists
                if current_interface and current_interface.name:
                    current_interface.zone_name = zone_lookup.get(current_interface.name)
                    # Filter by target_vdom if specified
                    if target_vdom is None or current_interface.vdom == target_vdom:
                        interfaces.append(current_interface)
                # Start new interface
                intf_name = edit_match.group(1).strip()
                current_interface = ParsedInterface(name=intf_name)
                # Default status to up for config mode (status down is explicitly set)
                current_interface.status = 'up'
                # Default vdom to "root" (FortiGate default)
                current_interface.vdom = 'root'
                continue

            # Detect block-style format: == [ interface_name ]
            block_match = re.match(r'^==\s*\[\s*([^\]]+)\s*\]', line_stripped)
            if block_match:
                parsing_mode = 'block'
                # Save previous interface if exists
                if current_interface and current_interface.name:
                    current_interface.zone_name = zone_lookup.get(current_interface.name)
                    # Filter by target_vdom if specified
                    if target_vdom is None or current_interface.vdom == target_vdom:
                        interfaces.append(current_interface)
                # Start new interface
                intf_name = block_match.group(1).strip()
                current_interface = ParsedInterface(name=intf_name)
                continue

            # Parse content based on mode
            if current_interface:
                if parsing_mode == 'config':
                    # Config-style parsing: set <key> <value>

                    # VDOM: set vdom "Campus"
                    vdom_match = re.match(r'^set\s+vdom\s+"?([^"]+)"?', line_stripped)
                    if vdom_match:
                        current_interface.vdom = vdom_match.group(1).strip()
                        continue

                    # IP address: set ip 10.10.101.254 255.255.255.0
                    ip_match = re.match(r'^set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line_stripped)
                    if ip_match:
                        ip = ip_match.group(1)
                        mask = ip_match.group(2)
                        if ip != '0.0.0.0' and mask != '0.0.0.0':
                            current_interface.ip_address = ip
                            current_interface.subnet_mask = mask
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                                current_interface.subnet_cidr = str(network)
                            except:
                                pass
                        continue

                    # Type: set type vlan/physical/aggregate/tunnel/loopback
                    type_match = re.match(r'^set\s+type\s+(\S+)', line_stripped)
                    if type_match:
                        current_interface.interface_type = type_match.group(1).lower()
                        continue

                    # Status: set status up/down
                    status_match = re.match(r'^set\s+status\s+(\S+)', line_stripped)
                    if status_match:
                        current_interface.status = status_match.group(1).lower()
                        continue

                    # Mode: set mode static/dhcp/pppoe
                    mode_match = re.match(r'^set\s+mode\s+(\S+)', line_stripped)
                    if mode_match:
                        current_interface.addressing_mode = mode_match.group(1).lower()
                        continue

                    # End of interface block
                    if line_stripped == 'next':
                        if current_interface and current_interface.name:
                            current_interface.zone_name = zone_lookup.get(current_interface.name)
                            # Filter by target_vdom if specified
                            if target_vdom is None or current_interface.vdom == target_vdom:
                                interfaces.append(current_interface)
                            current_interface = None
                        continue

                elif parsing_mode == 'block':
                    # Block-style parsing: key: value pairs

                    # VDOM: vdom: xxx
                    vdom_match = re.search(r'vdom:\s*(\S+)', line_stripped)
                    if vdom_match:
                        current_interface.vdom = vdom_match.group(1).strip()

                    # IP address with mask: ip: x.x.x.x y.y.y.y
                    ip_match = re.search(r'ip:\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line_stripped)
                    if ip_match:
                        ip = ip_match.group(1)
                        mask = ip_match.group(2)
                        if ip != '0.0.0.0' and mask != '0.0.0.0':
                            current_interface.ip_address = ip
                            current_interface.subnet_mask = mask
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                                current_interface.subnet_cidr = str(network)
                            except:
                                pass

                    # Mode: mode: static/dhcp/pppoe
                    mode_match = re.search(r'mode:\s*(\w+)', line_stripped)
                    if mode_match:
                        current_interface.addressing_mode = mode_match.group(1).lower()

                    # Status: status: up/down
                    status_match = re.search(r'status:\s*(\w+)', line_stripped)
                    if status_match:
                        current_interface.status = status_match.group(1).lower()

                    # Type: type: vlan/physical/etc
                    type_match = re.search(r'type:\s*(\w+)', line_stripped)
                    if type_match:
                        current_interface.interface_type = type_match.group(1).lower()

        # Don't forget the last interface
        if current_interface and current_interface.name:
            current_interface.zone_name = zone_lookup.get(current_interface.name)
            # Filter by target_vdom if specified
            if target_vdom is None or current_interface.vdom == target_vdom:
                interfaces.append(current_interface)

        return interfaces

    @classmethod
    async def fetch_zone_data(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession,
        vdom: Optional[str] = None
    ) -> Tuple[bool, str, Optional[ZoneSnapshot]]:
        """
        Fetch zone and interface data from FortiGate device.
        """
        start_time = time.time()

        # Check for SSH host override (same as routing service)
        ssh_host = device.ip_address
        ssh_host_result = await db.execute(
            select(DeviceSshSettings.ssh_host)
            .where(DeviceSshSettings.device_id == device.id)
            .limit(1)
        )
        ssh_host_override = ssh_host_result.scalar_one_or_none()
        if ssh_host_override:
            ssh_host = ssh_host_override.strip() or ssh_host

        # Build commands
        commands = []

        if vdom:
            vdom_clean = str(vdom).strip()
            vdom_arg = vdom_clean.replace('"', '\\"')
            edit_cmd = f'edit "{vdom_arg}"' if re.search(r"\s", vdom_arg) else f"edit {vdom_arg}"
            commands.append("config vdom")
            commands.append(edit_cmd)

        # Get zone and interface configuration
        # Note: "show system interface" returns only interfaces in current VDOM
        # "get system interface" returns ALL interfaces globally (wrong for VDOM filtering)
        commands.append("show system zone")
        commands.append("show system interface")

        if vdom:
            commands.append("end")

        vdom_display = f" (VDOM: {vdom})" if vdom else ""
        ssh_display = ssh_host if ssh_host != device.ip_address else device.ip_address
        logger.info(f"Fetching zone data from {device.ip_address} via {ssh_display}{vdom_display}")

        # Execute SSH commands in a thread to avoid blocking the event loop
        result = await asyncio.to_thread(
            SSHService.connect_interactive,
            host=ssh_host,
            username=credential.username,
            password=credential.password,
            commands=commands,
            port=credential.port or 22,
            prompt_pattern=r'[#$>]\s*$'
        )

        fetch_duration = int((time.time() - start_time) * 1000)

        if not result.success:
            # Create failed snapshot
            snapshot = ZoneSnapshot(
                device_id=device.id,
                vdom=vdom,
                raw_zone_output=result.output,
                raw_interface_output=None,
                zone_count=0,
                interface_count=0,
                fetch_duration_ms=fetch_duration,
                success=False,
                error_message=result.error or "SSH command failed"
            )
            db.add(snapshot)
            await db.commit()
            await db.refresh(snapshot)

            return False, result.error or "SSH command failed", snapshot

        # Split output to get zone and interface sections
        output = result.output

        # Find zone section
        zone_output = ""
        intf_output = ""

        # Look for zone config section
        zone_match = re.search(r'config system zone.*?(?=\n\S|$)', output, re.DOTALL)
        if zone_match:
            zone_output = zone_match.group(0)

        # Look for interface output - handles both 'show system interface' and 'get system interface'
        # First try to find 'show system interface' output
        intf_start = output.find('show system interface')
        if intf_start == -1:
            # Fallback to 'get system interface' if show wasn't found
            intf_start = output.find('get system interface')

        if intf_start != -1:
            # Get everything after the command
            intf_section = output[intf_start:]
            # Skip the command line itself
            lines = intf_section.split('\n')[1:]
            intf_output = '\n'.join(lines)

        # Parse the outputs
        zones = cls.parse_zone_output(zone_output)
        # Pass target_vdom to filter interfaces by VDOM assignment
        interfaces = cls.parse_interface_output(intf_output, zones, target_vdom=vdom)

        # Create snapshot
        snapshot = ZoneSnapshot(
            device_id=device.id,
            vdom=vdom,
            raw_zone_output=zone_output,
            raw_interface_output=intf_output,
            zone_count=len(zones),
            interface_count=len(interfaces),
            fetch_duration_ms=fetch_duration,
            success=True
        )
        db.add(snapshot)
        await db.flush()

        # Delete old entries for this device/vdom
        await db.execute(
            delete(ZoneEntry).where(
                and_(
                    ZoneEntry.device_id == device.id,
                    ZoneEntry.vdom == vdom if vdom else ZoneEntry.vdom.is_(None)
                )
            )
        )
        await db.execute(
            delete(InterfaceEntry).where(
                and_(
                    InterfaceEntry.device_id == device.id,
                    InterfaceEntry.vdom == vdom if vdom else InterfaceEntry.vdom.is_(None)
                )
            )
        )

        # Create zone entries
        for zone in zones:
            zone_entry = ZoneEntry(
                device_id=device.id,
                snapshot_id=snapshot.id,
                zone_name=zone.name,
                description=zone.description,
                intrazone=zone.intrazone,
                interfaces=zone.interfaces,
                vdom=vdom
            )
            db.add(zone_entry)

        # Create interface entries
        for intf in interfaces:
            intf_entry = InterfaceEntry(
                device_id=device.id,
                snapshot_id=snapshot.id,
                interface_name=intf.name,
                ip_address=intf.ip_address,
                subnet_mask=intf.subnet_mask,
                subnet_cidr=intf.subnet_cidr,
                interface_type=intf.interface_type,
                addressing_mode=intf.addressing_mode,
                status=intf.status,
                zone_name=intf.zone_name,
                vdom=vdom
            )
            db.add(intf_entry)

        await db.commit()
        await db.refresh(snapshot)

        logger.info(f"Successfully fetched {len(zones)} zones and {len(interfaces)} interfaces from {device.ip_address}")

        return True, f"Fetched {len(zones)} zones and {len(interfaces)} interfaces", snapshot

    @classmethod
    async def fetch_all_vdom_zone_data(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession
    ) -> Dict[str, Tuple[bool, str, Optional[ZoneSnapshot]]]:
        """
        Fetch zone data from all configured VDOMs for a device.
        """
        results = {}

        # Get configured VDOMs for the device
        vdom_result = await db.execute(
            select(DeviceVdom).where(
                and_(
                    DeviceVdom.device_id == device.id,
                    DeviceVdom.is_active == True
                )
            )
        )
        vdoms = vdom_result.scalars().all()

        if not vdoms:
            # No VDOMs configured, fetch global/root
            result = await cls.fetch_zone_data(device, credential, db, vdom=None)
            results['global'] = result
        else:
            # Fetch each VDOM
            for vdom in vdoms:
                result = await cls.fetch_zone_data(device, credential, db, vdom=vdom.vdom_name)
                results[vdom.vdom_name] = result

        return results

    @classmethod
    async def get_zone_interface_table(
        cls,
        device_id: int,
        db: AsyncSession,
        vdom: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get combined zone-interface-subnet table data for display.
        Returns a list of rows with zone, interface, and subnet info.
        """
        # Get zones
        zone_query = select(ZoneEntry).where(ZoneEntry.device_id == device_id)
        if vdom:
            zone_query = zone_query.where(ZoneEntry.vdom == vdom)
        zone_result = await db.execute(zone_query)
        zones = {z.zone_name: z for z in zone_result.scalars().all()}

        # Get interfaces
        intf_query = select(InterfaceEntry).where(InterfaceEntry.device_id == device_id)
        if vdom:
            intf_query = intf_query.where(InterfaceEntry.vdom == vdom)
        intf_result = await db.execute(intf_query)
        interfaces = intf_result.scalars().all()

        # Build table data
        table_data = []

        # Group interfaces by zone
        zone_interfaces = {}
        unzoned_interfaces = []

        for intf in interfaces:
            if intf.zone_name:
                if intf.zone_name not in zone_interfaces:
                    zone_interfaces[intf.zone_name] = []
                zone_interfaces[intf.zone_name].append(intf)
            else:
                unzoned_interfaces.append(intf)

        # Add zoned interfaces
        for zone_name, intfs in zone_interfaces.items():
            zone = zones.get(zone_name)
            for intf in intfs:
                table_data.append({
                    'zone_name': zone_name,
                    'zone_description': zone.description if zone else None,
                    'intrazone': zone.intrazone if zone else 'deny',
                    'interface_name': intf.interface_name,
                    'ip_address': intf.ip_address,
                    'subnet_mask': intf.subnet_mask,
                    'subnet_cidr': intf.subnet_cidr,
                    'interface_type': intf.interface_type,
                    'status': intf.status,
                    'vdom': intf.vdom
                })

        # Add unzoned interfaces (with IP only)
        for intf in unzoned_interfaces:
            if intf.ip_address:  # Only show interfaces with IPs
                table_data.append({
                    'zone_name': None,
                    'zone_description': None,
                    'intrazone': None,
                    'interface_name': intf.interface_name,
                    'ip_address': intf.ip_address,
                    'subnet_mask': intf.subnet_mask,
                    'subnet_cidr': intf.subnet_cidr,
                    'interface_type': intf.interface_type,
                    'status': intf.status,
                    'vdom': intf.vdom
                })

        # Sort by zone name (None last), then interface name
        table_data.sort(key=lambda x: (x['zone_name'] is None, x['zone_name'] or '', x['interface_name']))

        return table_data

    @classmethod
    async def get_latest_snapshot(
        cls,
        device_id: int,
        db: AsyncSession,
        vdom: Optional[str] = None
    ) -> Optional[ZoneSnapshot]:
        """Get the latest zone snapshot for a device."""
        query = (
            select(ZoneSnapshot)
            .where(
                and_(
                    ZoneSnapshot.device_id == device_id,
                    ZoneSnapshot.success == True
                )
            )
            .order_by(ZoneSnapshot.fetched_at.desc())
            .limit(1)
        )
        if vdom:
            query = query.where(ZoneSnapshot.vdom == vdom)

        result = await db.execute(query)
        return result.scalar_one_or_none()
