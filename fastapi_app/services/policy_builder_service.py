"""
Policy Builder Service - Generate firewall CLI commands from log data.
Supports both FortiGate (Fortinet) and Palo Alto Networks firewalls.
"""

import ipaddress
import logging
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class FirewallVendor(str, Enum):
    """Supported firewall vendors."""
    FORTINET = "fortinet"
    PALOALTO = "paloalto"


# Standard FortiGate service port mappings
STANDARD_SERVICES = {
    # TCP Services
    (20, 'tcp'): 'FTP_DATA',
    (21, 'tcp'): 'FTP',
    (22, 'tcp'): 'SSH',
    (23, 'tcp'): 'TELNET',
    (25, 'tcp'): 'SMTP',
    (53, 'tcp'): 'DNS',
    (80, 'tcp'): 'HTTP',
    (110, 'tcp'): 'POP3',
    (143, 'tcp'): 'IMAP',
    (443, 'tcp'): 'HTTPS',
    (445, 'tcp'): 'SMB',
    (465, 'tcp'): 'SMTPS',
    (587, 'tcp'): 'SMTP_587',
    (993, 'tcp'): 'IMAPS',
    (995, 'tcp'): 'POP3S',
    (1433, 'tcp'): 'MS-SQL',
    (1521, 'tcp'): 'Oracle-DB',
    (3306, 'tcp'): 'MYSQL',
    (3389, 'tcp'): 'RDP',
    (5432, 'tcp'): 'PostgreSQL',
    (8080, 'tcp'): 'HTTP-ALT',
    (8443, 'tcp'): 'HTTPS-ALT',
    # UDP Services
    (53, 'udp'): 'DNS',
    (67, 'udp'): 'DHCP',
    (68, 'udp'): 'DHCP',
    (69, 'udp'): 'TFTP',
    (123, 'udp'): 'NTP',
    (161, 'udp'): 'SNMP',
    (162, 'udp'): 'SNMP_TRAP',
    (514, 'udp'): 'SYSLOG',
}

# ICMP type mappings to FortiGate service names
ICMP_SERVICES = {
    0: 'PING',          # Echo Reply
    8: 'PING',          # Echo Request
    3: 'ALL_ICMP',      # Destination Unreachable
    11: 'ALL_ICMP',     # Time Exceeded
    'any': 'ALL_ICMP',  # Any ICMP type
}

# Standard Palo Alto application/service mappings
PALOALTO_SERVICES = {
    # TCP Services - maps to application-default or well-known ports
    (20, 'tcp'): 'ftp-data',
    (21, 'tcp'): 'ftp',
    (22, 'tcp'): 'ssh',
    (23, 'tcp'): 'telnet',
    (25, 'tcp'): 'smtp',
    (53, 'tcp'): 'dns',
    (80, 'tcp'): 'web-browsing',
    (110, 'tcp'): 'pop3',
    (143, 'tcp'): 'imap',
    (443, 'tcp'): 'ssl',
    (445, 'tcp'): 'ms-ds-smb',
    (465, 'tcp'): 'smtp',
    (587, 'tcp'): 'smtp',
    (993, 'tcp'): 'imap',
    (995, 'tcp'): 'pop3',
    (1433, 'tcp'): 'mssql-db',
    (1521, 'tcp'): 'oracle',
    (3306, 'tcp'): 'mysql',
    (3389, 'tcp'): 'ms-rdp',
    (5432, 'tcp'): 'postgres',
    (8080, 'tcp'): 'web-browsing',
    (8443, 'tcp'): 'ssl',
    # UDP Services
    (53, 'udp'): 'dns',
    (67, 'udp'): 'dhcp',
    (68, 'udp'): 'dhcp',
    (69, 'udp'): 'tftp',
    (123, 'udp'): 'ntp',
    (161, 'udp'): 'snmp',
    (162, 'udp'): 'snmp-trap',
    (514, 'udp'): 'syslog',
}

# ICMP type mappings for Palo Alto
PALOALTO_ICMP_SERVICES = {
    0: 'ping',          # Echo Reply
    8: 'ping',          # Echo Request
    3: 'icmp',          # Destination Unreachable
    11: 'icmp',         # Time Exceeded
    'any': 'icmp',      # Any ICMP type
}


@dataclass
class PolicyData:
    """Data structure for policy generation."""
    srcip: str
    dstip: str
    dstport: int
    protocol: str  # 'tcp', 'udp', 'icmp', or protocol number
    srczone: Optional[str] = None
    dstzone: Optional[str] = None
    srcintf: Optional[str] = None
    dstintf: Optional[str] = None
    service_name: Optional[str] = None
    action: str = 'accept'
    policy_name: Optional[str] = None
    comment: Optional[str] = None
    vdom: Optional[str] = None


class PolicyBuilderService:
    """Service for building FortiGate CLI policy commands."""

    @staticmethod
    def normalize_protocol(proto: Any) -> str:
        """Normalize protocol value to string format."""
        if proto is None:
            return 'any'
        proto_str = str(proto).lower().strip()

        # Map protocol numbers to names
        proto_map = {
            '6': 'tcp',
            '17': 'udp',
            '1': 'icmp',
            '0': 'any',
        }
        return proto_map.get(proto_str, proto_str)

    @staticmethod
    def ip_to_zone(ip: str, zone_table: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Match an IP address to a zone using subnet CIDR from zone table.

        Args:
            ip: IP address to match
            zone_table: List of zone/interface data with subnet_cidr

        Returns:
            Matching zone entry dict or None
        """
        if not ip or not zone_table:
            return None

        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return None

        best_match = None
        best_prefix_len = -1

        for entry in zone_table:
            subnet_cidr = entry.get('subnet_cidr')
            if not subnet_cidr:
                continue

            try:
                network = ipaddress.ip_network(subnet_cidr, strict=False)
                if ip_addr in network:
                    # Prefer more specific matches (longer prefix)
                    if network.prefixlen > best_prefix_len:
                        best_prefix_len = network.prefixlen
                        best_match = entry
            except ValueError:
                continue

        return best_match

    @staticmethod
    def interface_to_zone(interface_name: str, zone_table: List[Dict[str, Any]]) -> Optional[str]:
        """
        Look up the zone name for a given interface from zone table.

        Args:
            interface_name: Interface name to look up (e.g., "VLAN235", "port16")
            zone_table: List of zone/interface data

        Returns:
            Zone name if found, None otherwise
        """
        if not interface_name or not zone_table:
            return None

        # Normalize interface name for comparison
        intf_lower = interface_name.lower().strip()

        for entry in zone_table:
            entry_intf = entry.get('interface_name', '')
            if entry_intf and entry_intf.lower().strip() == intf_lower:
                zone_name = entry.get('zone_name')
                if zone_name:
                    return zone_name

        return None

    @staticmethod
    def generate_address_object_name(ip: str, prefix: str = "addr") -> str:
        """Generate a valid FortiGate address object name."""
        # Replace dots and slashes for valid object name
        safe_ip = ip.replace('.', '_').replace('/', '_')
        return f"{prefix}_{safe_ip}"

    @staticmethod
    def generate_service_object_name(port: int, protocol: str) -> str:
        """Generate a valid FortiGate service object name."""
        return f"svc_{protocol.upper()}_{port}"

    @classmethod
    def get_service_name(cls, port: int, protocol: str) -> str:
        """
        Get the service name for a port/protocol combination.
        Returns standard service name if available, otherwise generates custom name.
        """
        proto_lower = protocol.lower()

        # Handle ICMP protocol (doesn't use ports)
        if proto_lower in ('icmp', '1'):
            # port might contain ICMP type, or be 0/None for "any"
            icmp_type = port if port else 'any'
            return ICMP_SERVICES.get(icmp_type, 'ALL_ICMP')

        # Check standard services
        key = (port, proto_lower)
        if key in STANDARD_SERVICES:
            return STANDARD_SERVICES[key]

        # Generate custom service name
        return cls.generate_service_object_name(port, proto_lower)

    @classmethod
    def build_address_object_cli(cls, ip: str, name: Optional[str] = None) -> str:
        """
        Generate FortiGate CLI for address object.

        Args:
            ip: IP address (can be single IP or CIDR)
            name: Optional custom name for the object
        """
        obj_name = name or cls.generate_address_object_name(ip)

        # Determine if it's a subnet or single host
        if '/' in ip:
            # It's a subnet
            try:
                network = ipaddress.ip_network(ip, strict=False)
                subnet = str(network.network_address)
                mask = str(network.netmask)
            except ValueError:
                subnet = ip.split('/')[0]
                mask = "255.255.255.255"
        else:
            # Single host
            subnet = ip
            mask = "255.255.255.255"

        cli = f'''config firewall address
    edit "{obj_name}"
        set subnet {subnet} {mask}
    next
end'''
        return cli

    @classmethod
    def build_service_object_cli(cls, port: int, protocol: str, name: Optional[str] = None) -> Optional[str]:
        """
        Generate FortiGate CLI for custom service object.
        Returns None if standard service exists.

        Args:
            port: Destination port number
            protocol: Protocol (tcp, udp, icmp)
            name: Optional custom name for the object
        """
        proto_lower = protocol.lower()

        # ICMP uses standard FortiGate services, no custom object needed
        if proto_lower in ('icmp', '1'):
            return None

        # Check if standard service exists
        if (port, proto_lower) in STANDARD_SERVICES:
            return None

        obj_name = name or cls.generate_service_object_name(port, proto_lower)
        proto_upper = proto_lower.upper()

        cli = f'''config firewall service custom
    edit "{obj_name}"
        set {proto_upper.lower()}-portrange {port}
    next
end'''
        return cli

    @classmethod
    def build_policy_cli(
        cls,
        policy_data: PolicyData,
        policy_id: Optional[int] = None,
        zone_table: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate complete FortiGate CLI for a firewall policy.

        Args:
            policy_data: PolicyData object with all necessary info
            policy_id: Optional policy ID (use 0 for auto-assign)
            zone_table: Optional zone/interface table for IP-to-zone matching

        Returns:
            Dict with 'cli' (full CLI string) and 'components' (individual parts)
        """
        result = {
            'cli': '',
            'components': {
                'address_objects': [],
                'service_objects': [],
                'policy': ''
            },
            'metadata': {}
        }

        # Normalize protocol
        protocol = cls.normalize_protocol(policy_data.protocol)

        # Determine zones from IP if not provided
        srczone = policy_data.srczone
        dstzone = policy_data.dstzone
        srcintf = policy_data.srcintf
        dstintf = policy_data.dstintf

        if zone_table:
            # Always try IP-to-zone matching for zone lookup
            # This is preferred because the source IP belongs to a specific subnet/zone
            # even if the log shows a different egress interface (e.g., WAN interface)
            if not srczone:
                src_match = cls.ip_to_zone(policy_data.srcip, zone_table)
                if src_match:
                    srczone = src_match.get('zone_name') or 'any'
                    if not srcintf:
                        srcintf = src_match.get('interface_name') or 'any'
                    result['metadata']['src_subnet'] = src_match.get('subnet_cidr')

            if not dstzone:
                dst_match = cls.ip_to_zone(policy_data.dstip, zone_table)
                if dst_match:
                    dstzone = dst_match.get('zone_name') or 'any'
                    if not dstintf:
                        dstintf = dst_match.get('interface_name') or 'any'
                    result['metadata']['dst_subnet'] = dst_match.get('subnet_cidr')

            # Fallback: Look up zone by interface name if we still have no zone
            # This handles cases where IP doesn't match any subnet but interface is in a zone
            if srcintf and (not srczone or srczone == 'any'):
                zone_from_intf = cls.interface_to_zone(srcintf, zone_table)
                if zone_from_intf:
                    srczone = zone_from_intf

            if dstintf and (not dstzone or dstzone == 'any'):
                zone_from_intf = cls.interface_to_zone(dstintf, zone_table)
                if zone_from_intf:
                    dstzone = zone_from_intf

        # Use defaults if still not determined
        srczone = srczone or 'any'
        dstzone = dstzone or 'any'
        srcintf = srcintf or 'any'
        dstintf = dstintf or 'any'

        # FortiGate policy logic: If zone is defined (not 'any'), use zone for srcintf/dstintf
        # If zone is 'any' or not defined, use the interface name
        policy_srcintf = srczone if srczone and srczone != 'any' else srcintf
        policy_dstintf = dstzone if dstzone and dstzone != 'any' else dstintf

        result['metadata']['srczone'] = srczone
        result['metadata']['dstzone'] = dstzone
        result['metadata']['srcintf'] = srcintf
        result['metadata']['dstintf'] = dstintf
        result['metadata']['policy_srcintf'] = policy_srcintf
        result['metadata']['policy_dstintf'] = policy_dstintf

        # Build CLI components
        cli_parts = []

        # 1. Source Address Object
        src_addr_name = cls.generate_address_object_name(policy_data.srcip, "src")
        src_addr_cli = cls.build_address_object_cli(policy_data.srcip, src_addr_name)
        cli_parts.append(src_addr_cli)
        result['components']['address_objects'].append({
            'name': src_addr_name,
            'ip': policy_data.srcip,
            'cli': src_addr_cli
        })

        # 2. Destination Address Object
        dst_addr_name = cls.generate_address_object_name(policy_data.dstip, "dst")
        dst_addr_cli = cls.build_address_object_cli(policy_data.dstip, dst_addr_name)
        cli_parts.append(dst_addr_cli)
        result['components']['address_objects'].append({
            'name': dst_addr_name,
            'ip': policy_data.dstip,
            'cli': dst_addr_cli
        })

        # 3. Service Object (if custom port)
        service_name = cls.get_service_name(policy_data.dstport, protocol)
        svc_cli = cls.build_service_object_cli(policy_data.dstport, protocol)
        if svc_cli:
            cli_parts.append(svc_cli)
            result['components']['service_objects'].append({
                'name': service_name,
                'port': policy_data.dstport,
                'protocol': protocol,
                'cli': svc_cli
            })

        result['metadata']['service_name'] = service_name
        result['metadata']['is_standard_service'] = svc_cli is None

        # 4. Firewall Policy
        policy_id_str = str(policy_id) if policy_id else '0'

        # Generate policy name and comment based on protocol
        if protocol in ('icmp', '1'):
            policy_name = policy_data.policy_name or f"Allow_ICMP"
            comment = policy_data.comment or f"Auto-generated policy to allow ICMP from {policy_data.srcip} to {policy_data.dstip}"
        else:
            policy_name = policy_data.policy_name or f"Allow_{protocol.upper()}_{policy_data.dstport}"
            comment = policy_data.comment or f"Auto-generated policy to allow {protocol.upper()}/{policy_data.dstport} from {policy_data.srcip} to {policy_data.dstip}"

        policy_cli = f'''config firewall policy
    edit {policy_id_str}
        set name "{policy_name}"
        set srcintf "{policy_srcintf}"
        set dstintf "{policy_dstintf}"
        set srcaddr "{src_addr_name}"
        set dstaddr "{dst_addr_name}"
        set action accept
        set schedule "always"
        set service "{service_name}"
        set logtraffic all
        set comments "{comment}"
    next
end'''

        cli_parts.append(policy_cli)
        result['components']['policy'] = policy_cli

        # VDOM prefix if specified
        vdom_prefix = ""
        vdom_suffix = ""
        if policy_data.vdom:
            vdom_prefix = f'''config vdom
edit "{policy_data.vdom}"
'''
            vdom_suffix = '''
end'''

        # Combine all CLI parts
        result['cli'] = vdom_prefix + '\n\n'.join(cli_parts) + vdom_suffix

        return result

    # ============================================================
    # Palo Alto Networks CLI Generation Methods
    # ============================================================

    @classmethod
    def get_paloalto_service_name(cls, port: int, protocol: str) -> str:
        """
        Get the Palo Alto service/application name for a port/protocol combination.
        """
        proto_lower = protocol.lower()

        # Handle ICMP protocol
        if proto_lower in ('icmp', '1'):
            icmp_type = port if port else 'any'
            return PALOALTO_ICMP_SERVICES.get(icmp_type, 'icmp')

        # Check Palo Alto service mappings
        key = (port, proto_lower)
        if key in PALOALTO_SERVICES:
            return PALOALTO_SERVICES[key]

        # For custom ports, we'll use service objects
        return f"svc-{proto_lower}-{port}"

    @classmethod
    def generate_paloalto_address_name(cls, ip: str, prefix: str = "addr") -> str:
        """Generate a valid Palo Alto address object name."""
        safe_ip = ip.replace('.', '-').replace('/', '-')
        return f"{prefix}-{safe_ip}"

    @classmethod
    def build_paloalto_address_cli(cls, ip: str, name: Optional[str] = None) -> str:
        """
        Generate Palo Alto CLI for address object.
        """
        obj_name = name or cls.generate_paloalto_address_name(ip)

        # Determine if it's a subnet or single host
        if '/' in ip:
            # It's a subnet - use ip-netmask
            cli = f'''set address {obj_name} ip-netmask {ip}'''
        else:
            # Single host - use /32 notation
            cli = f'''set address {obj_name} ip-netmask {ip}/32'''

        return cli

    @classmethod
    def build_paloalto_service_cli(cls, port: int, protocol: str, name: Optional[str] = None) -> Optional[str]:
        """
        Generate Palo Alto CLI for custom service object.
        Returns None if standard service exists.
        """
        proto_lower = protocol.lower()

        # ICMP uses standard applications, no custom service needed
        if proto_lower in ('icmp', '1'):
            return None

        # Check if standard service exists
        if (port, proto_lower) in PALOALTO_SERVICES:
            return None

        obj_name = name or f"svc-{proto_lower}-{port}"

        cli = f'''set service {obj_name} protocol {proto_lower} port {port}'''
        return cli

    @classmethod
    def build_paloalto_policy_cli(
        cls,
        policy_data: PolicyData,
        zone_table: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate complete Palo Alto CLI for a security policy.

        Args:
            policy_data: PolicyData object with all necessary info
            zone_table: Optional zone/interface table for IP-to-zone matching

        Returns:
            Dict with 'cli' (full CLI string) and 'components' (individual parts)
        """
        result = {
            'cli': '',
            'components': {
                'address_objects': [],
                'service_objects': [],
                'policy': ''
            },
            'metadata': {}
        }

        # Normalize protocol
        protocol = cls.normalize_protocol(policy_data.protocol)

        # Determine zones
        srczone = policy_data.srczone
        dstzone = policy_data.dstzone

        if zone_table:
            if not srczone:
                src_match = cls.ip_to_zone(policy_data.srcip, zone_table)
                if src_match:
                    srczone = src_match.get('zone_name') or 'any'
                    result['metadata']['src_subnet'] = src_match.get('subnet_cidr')

            if not dstzone:
                dst_match = cls.ip_to_zone(policy_data.dstip, zone_table)
                if dst_match:
                    dstzone = dst_match.get('zone_name') or 'any'
                    result['metadata']['dst_subnet'] = dst_match.get('subnet_cidr')

        # Use defaults if not determined
        srczone = srczone or 'trust'
        dstzone = dstzone or 'untrust'

        result['metadata']['srczone'] = srczone
        result['metadata']['dstzone'] = dstzone

        # Build CLI components
        cli_parts = []

        # 1. Source Address Object
        src_addr_name = cls.generate_paloalto_address_name(policy_data.srcip, "src")
        src_addr_cli = cls.build_paloalto_address_cli(policy_data.srcip, src_addr_name)
        cli_parts.append(src_addr_cli)
        result['components']['address_objects'].append({
            'name': src_addr_name,
            'ip': policy_data.srcip,
            'cli': src_addr_cli
        })

        # 2. Destination Address Object
        dst_addr_name = cls.generate_paloalto_address_name(policy_data.dstip, "dst")
        dst_addr_cli = cls.build_paloalto_address_cli(policy_data.dstip, dst_addr_name)
        cli_parts.append(dst_addr_cli)
        result['components']['address_objects'].append({
            'name': dst_addr_name,
            'ip': policy_data.dstip,
            'cli': dst_addr_cli
        })

        # 3. Service Object (if custom port)
        service_name = cls.get_paloalto_service_name(policy_data.dstport, protocol)
        svc_cli = cls.build_paloalto_service_cli(policy_data.dstport, protocol)
        if svc_cli:
            cli_parts.append(svc_cli)
            result['components']['service_objects'].append({
                'name': service_name,
                'port': policy_data.dstport,
                'protocol': protocol,
                'cli': svc_cli
            })

        result['metadata']['service_name'] = service_name
        result['metadata']['is_standard_service'] = svc_cli is None

        # 4. Security Policy
        # Generate policy name and description
        if protocol in ('icmp', '1'):
            policy_name = policy_data.policy_name or "Allow-ICMP"
            description = policy_data.comment or f"Allow ICMP from {policy_data.srcip} to {policy_data.dstip}"
        else:
            policy_name = policy_data.policy_name or f"Allow-{protocol.upper()}-{policy_data.dstport}"
            description = policy_data.comment or f"Allow {protocol.upper()}/{policy_data.dstport} from {policy_data.srcip} to {policy_data.dstip}"

        # Determine application and service
        if protocol in ('icmp', '1'):
            app_setting = 'ping'
            service_setting = 'application-default'
        elif (policy_data.dstport, protocol) in PALOALTO_SERVICES:
            # For well-known ports, use application-default
            app_setting = PALOALTO_SERVICES.get((policy_data.dstport, protocol), 'any')
            service_setting = 'application-default'
        else:
            # For custom ports, use the custom service
            app_setting = 'any'
            service_setting = service_name

        # Build security policy rule
        policy_cli = f'''set rulebase security rules {policy_name} from {srczone}
set rulebase security rules {policy_name} to {dstzone}
set rulebase security rules {policy_name} source {src_addr_name}
set rulebase security rules {policy_name} destination {dst_addr_name}
set rulebase security rules {policy_name} application {app_setting}
set rulebase security rules {policy_name} service {service_setting}
set rulebase security rules {policy_name} action allow
set rulebase security rules {policy_name} log-end yes
set rulebase security rules {policy_name} description "{description}"'''

        cli_parts.append(policy_cli)
        result['components']['policy'] = policy_cli

        # Device group prefix if specified (for Panorama)
        device_group_prefix = ""
        if policy_data.vdom:  # Using vdom field for device-group in Palo Alto context
            device_group_prefix = f"# Device Group: {policy_data.vdom}\n"

        # Combine all CLI parts with commit instruction
        result['cli'] = device_group_prefix + '\n'.join(cli_parts) + '\n\ncommit'

        return result

    @classmethod
    def build_policy_from_log(
        cls,
        log_data: Dict[str, Any],
        zone_table: Optional[List[Dict[str, Any]]] = None,
        vdom: Optional[str] = None,
        custom_name: Optional[str] = None,
        vendor: str = "fortinet"
    ) -> Dict[str, Any]:
        """
        Build firewall CLI from a log entry's parsed_data.

        Args:
            log_data: Log entry dict (contains 'parsed_data' or direct fields)
            zone_table: Zone/interface table for IP-to-zone matching
            vdom: Optional VDOM name
            custom_name: Optional custom policy name
            vendor: Firewall vendor - 'fortinet' or 'paloalto'

        Returns:
            Dict with CLI and metadata
        """
        # Normalize vendor
        vendor = vendor.lower() if vendor else "fortinet"

        pd = log_data.get('parsed_data', {})

        # Extract fields from log data (try multiple field names)
        srcip = (log_data.get('srcip') or
                 pd.get('srcip') or pd.get('src_ip') or 'any')
        dstip = (log_data.get('dstip') or
                 pd.get('dstip') or pd.get('dst_ip') or 'any')
        dstport = (log_data.get('dstport') or
                   pd.get('dstport') or pd.get('dst_port') or 0)
        proto = (log_data.get('proto') or
                 pd.get('proto') or pd.get('protocol') or 'tcp')

        # Extract zone info - try multiple field names used by different firewall vendors
        srczone = (pd.get('srczone') or pd.get('src_zone') or
                   pd.get('from_zone') or pd.get('from') or
                   log_data.get('srczone'))
        dstzone = (pd.get('dstzone') or pd.get('dst_zone') or
                   pd.get('to_zone') or pd.get('to') or
                   log_data.get('dstzone'))

        # Extract interface info
        srcintf = (pd.get('srcintf') or pd.get('inbound_if') or
                   pd.get('srcintfname') or log_data.get('srcintf'))
        dstintf = (pd.get('dstintf') or pd.get('outbound_if') or
                   pd.get('dstintfname') or log_data.get('dstintf'))

        # Ensure port is an integer
        try:
            dstport = int(dstport) if dstport else 0
        except (ValueError, TypeError):
            dstport = 0

        # Create policy data
        policy_data = PolicyData(
            srcip=srcip,
            dstip=dstip,
            dstport=dstport,
            protocol=proto,
            srczone=srczone,
            dstzone=dstzone,
            srcintf=srcintf,
            dstintf=dstintf,
            policy_name=custom_name,
            vdom=vdom
        )

        # Call appropriate vendor-specific method
        if vendor == "paloalto":
            result = cls.build_paloalto_policy_cli(policy_data, zone_table=zone_table)
        else:
            result = cls.build_policy_cli(policy_data, zone_table=zone_table)

        # Add vendor to metadata
        result['metadata']['vendor'] = vendor

        return result
