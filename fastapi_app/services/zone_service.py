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

from ..models.device import Device, ParserType
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


def _scrub_for_pg_text(s):
    """Strip characters Postgres TEXT cannot store (NUL/0x00 + other C0
    controls). SSH/terminal capture often includes these; without scrubbing
    Postgres rejects the row with `CharacterNotInRepertoireError`."""
    if s is None:
        return None
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return None
    return s.translate({i: None for i in range(0x20) if i not in (0x09, 0x0A, 0x0D)})


class ZoneService:
    """Service for managing zone/interface data across vendors (Fortinet, PAN-OS)."""

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

    @staticmethod
    def parse_paloalto_interface_output(
        raw_output: str,
        target_vsys: Optional[str] = None,
    ) -> Tuple[List[ParsedZone], List[ParsedInterface]]:
        """
        Parse PAN-OS `show interface all` output.

        The command emits two fixed-width tables:

          total configured hardware interfaces: N
          name                id   speed/duplex/state    mac address
          ethernet1/1         16   10000/full/up         00:50:56:0b:68:05

          total configured logical interfaces: N
          name              id    vsys zone             forwarding         tag    address
          ethernet1/3       18    1    INTERNET         vr:default         0      192.168.201.254/24
          ethernet1/1       16    1                     ha                 0      192.168.200.2/28

        Two tricky bits:
          - the `zone` column is often empty (e.g. ha-link interfaces); a
            naive .split() collapses the whitespace and shifts every column
            to the left. We therefore parse by character positions taken
            from the column header line.
          - some interfaces have continuation lines holding additional IPs;
            those lines have no name/id and we skip them (we only keep the
            primary IP for the table view).
        """
        if not raw_output:
            return [], []

        # Strip ANSI/CR artefacts paramiko leaves behind.
        cleaned = raw_output.replace("\r", "")
        ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
        cleaned = ANSI_RE.sub("", cleaned)

        ifaces_by_name: Dict[str, ParsedInterface] = {}

        def _slice(line: str, start: int, end: Optional[int]) -> str:
            return (line[start:end] if end is not None else line[start:]).strip()

        def _header_columns(header: str, fields: List[str]) -> Optional[Dict[str, int]]:
            """Return start position of each header field (or None if any missing)."""
            positions: Dict[str, int] = {}
            for f in fields:
                m = re.search(r'\b' + re.escape(f) + r'\b', header)
                if not m:
                    return None
                positions[f] = m.start()
            return positions

        lines = cleaned.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i]

            # Hardware-interface table header → next data lines until blank.
            if re.search(r'\bname\b\s+\bid\b\s+\bspeed/duplex/state\b', line):
                positions = _header_columns(line, ['name', 'id', 'speed/duplex/state', 'mac address'])
                # Build slice ranges from positions
                sorted_cols = sorted(positions.items(), key=lambda kv: kv[1])
                col_ranges = {}
                for idx_c, (col, start) in enumerate(sorted_cols):
                    end = sorted_cols[idx_c + 1][1] if idx_c + 1 < len(sorted_cols) else None
                    col_ranges[col] = (start, end)
                i += 1
                # Skip optional separator line (---)
                if i < len(lines) and set(lines[i].strip()) <= {'-'}:
                    i += 1
                while i < len(lines):
                    row = lines[i]
                    if not row.strip():
                        break
                    name = _slice(row, *col_ranges['name'])
                    if not re.match(r'^[A-Za-z][\w./-]*$', name):
                        break
                    iface = ifaces_by_name.setdefault(name, ParsedInterface(name=name))
                    state_field = _slice(row, *col_ranges['speed/duplex/state'])
                    m = re.search(r'/([A-Za-z]+)$', state_field)
                    if m:
                        iface.status = m.group(1).lower()
                    i += 1
                continue

            # Logical-interface table header.
            if re.search(r'\bname\b.*\bvsys\b.*\bzone\b', line):
                fields = ['name', 'id', 'vsys', 'zone', 'forwarding', 'tag', 'address']
                positions = _header_columns(line, fields)
                if not positions:
                    i += 1
                    continue
                sorted_cols = sorted(positions.items(), key=lambda kv: kv[1])
                col_ranges = {}
                for idx_c, (col, start) in enumerate(sorted_cols):
                    end = sorted_cols[idx_c + 1][1] if idx_c + 1 < len(sorted_cols) else None
                    col_ranges[col] = (start, end)
                i += 1
                if i < len(lines) and set(lines[i].strip()) <= {'-', ' '}:
                    i += 1
                while i < len(lines):
                    row = lines[i]
                    if not row.strip():
                        break
                    name = _slice(row, *col_ranges['name'])
                    # Continuation lines (extra IPs) have an empty name col.
                    if not name or not re.match(r'^[A-Za-z][\w./-]*$', name):
                        i += 1
                        continue
                    iface = ifaces_by_name.setdefault(name, ParsedInterface(name=name))
                    vsys_val = _slice(row, *col_ranges['vsys'])
                    zone_val = _slice(row, *col_ranges['zone'])
                    addr_val = _slice(row, *col_ranges['address'])

                    if vsys_val:
                        iface.vdom = vsys_val  # repurpose vdom slot for vsys id
                    if zone_val and zone_val.lower() != 'untagged':
                        iface.zone_name = zone_val
                    # The address column can drift past its header position when
                    # earlier fields (forwarding, tag) overflow their width, so
                    # prefer a regex search over the right portion of the line.
                    addr_search_from = col_ranges['tag'][0] if 'tag' in col_ranges else 0
                    addr_match = re.search(
                        r'\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b',
                        row[addr_search_from:],
                    )
                    if addr_match:
                        cidr = addr_match.group(1)
                        iface.subnet_cidr = cidr
                        ip, _ = cidr.split('/', 1)
                        iface.ip_address = ip
                        try:
                            iface.subnet_mask = str(
                                ipaddress.IPv4Network(cidr, strict=False).netmask
                            )
                        except (ValueError, ipaddress.AddressValueError):
                            pass
                    i += 1
                continue

            i += 1

        # Filter by vsys (PAN's vsys lives in the .vdom slot here).
        interfaces = [
            ifc for ifc in ifaces_by_name.values()
            if target_vsys is None or ifc.vdom == target_vsys
        ]

        # Derive zones from distinct zone names referenced.
        zone_to_intfs: Dict[str, List[str]] = {}
        for ifc in interfaces:
            if ifc.zone_name:
                zone_to_intfs.setdefault(ifc.zone_name, []).append(ifc.name)
        zones = [
            ParsedZone(name=name, interfaces=intfs)
            for name, intfs in sorted(zone_to_intfs.items())
        ]

        return zones, interfaces

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

        # device.ip_address is INET → IPv4Address; coerce to str for paramiko.
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

        vdom_display = f" (VDOM/vsys: {vdom})" if vdom else ""
        logger.info(f"Fetching zone data from {device.ip_address} ({device.parser}){vdom_display}")

        # Vendor-aware fetch.
        if device.parser == ParserType.FORTINET:
            commands = []
            if vdom:
                vdom_clean = str(vdom).strip()
                vdom_arg = vdom_clean.replace('"', '\\"')
                edit_cmd = f'edit "{vdom_arg}"' if re.search(r"\s", vdom_arg) else f"edit {vdom_arg}"
                commands.append("config vdom")
                commands.append(edit_cmd)
            # `show system interface` returns only interfaces in current VDOM;
            # `get system interface` returns all globally (wrong for VDOM scope).
            commands.append("show system zone")
            commands.append("show system interface")
            if vdom:
                commands.append("end")

            result = await asyncio.to_thread(
                SSHService.connect_interactive,
                host=ssh_host,
                username=credential.username,
                password=credential.password,
                commands=commands,
                port=credential.port or 22,
                prompt_pattern=r'[#$>]\s*$',
                prompt_timeout=15,
            )
        elif device.parser == ParserType.PALOALTO:
            result = await asyncio.to_thread(
                SSHService.get_paloalto_zone_data,
                host=ssh_host,
                username=credential.username,
                password=credential.password,
                port=credential.port or 22,
                vsys=vdom,  # PAN's vsys takes the same slot Fortinet uses for VDOM
            )
        else:
            return False, f"Unsupported device type: {device.parser}", None

        fetch_duration = int((time.time() - start_time) * 1000)

        if not result.success:
            # Create failed snapshot. Scrub raw output of NUL/control bytes
            # that Postgres TEXT cannot store (CharacterNotInRepertoireError).
            snapshot = ZoneSnapshot(
                device_id=device.id,
                vdom=vdom,
                raw_zone_output=_scrub_for_pg_text(result.output),
                raw_interface_output=None,
                zone_count=0,
                interface_count=0,
                fetch_duration_ms=fetch_duration,
                success=False,
                error_message=_scrub_for_pg_text(result.error) or "SSH command failed",
            )
            db.add(snapshot)
            await db.commit()
            await db.refresh(snapshot)

            return False, result.error or "SSH command failed", snapshot

        output = result.output

        # Vendor-aware parsing.
        if device.parser == ParserType.PALOALTO:
            zone_output = ""  # PAN gets both from one command
            intf_output = output
            zones, interfaces = cls.parse_paloalto_interface_output(output, target_vsys=vdom)
        else:
            # Fortinet: split into the two sub-outputs first.
            zone_output = ""
            intf_output = ""
            zone_match = re.search(r'config system zone.*?(?=\n\S|$)', output, re.DOTALL)
            if zone_match:
                zone_output = zone_match.group(0)
            intf_start = output.find('show system interface')
            if intf_start == -1:
                intf_start = output.find('get system interface')
            if intf_start != -1:
                intf_section = output[intf_start:]
                lines = intf_section.split('\n')[1:]
                intf_output = '\n'.join(lines)
            zones = cls.parse_zone_output(zone_output)
            interfaces = cls.parse_interface_output(intf_output, zones, target_vdom=vdom)

        # Create snapshot. Scrub raw output of NUL/control bytes that Postgres
        # TEXT cannot store (CharacterNotInRepertoireError).
        snapshot = ZoneSnapshot(
            device_id=device.id,
            vdom=vdom,
            raw_zone_output=_scrub_for_pg_text(zone_output),
            raw_interface_output=_scrub_for_pg_text(intf_output),
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
