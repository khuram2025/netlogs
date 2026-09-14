"""
Routing Table Parser - Parse routing table output from various firewall vendors.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ParsedRoute:
    """Parsed routing entry."""
    route_type: str
    network: str
    prefix_length: int
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    admin_distance: Optional[int] = None
    metric: Optional[int] = None
    preference: Optional[str] = None
    age: Optional[str] = None
    is_default: bool = False
    is_recursive: bool = False
    recursive_via: Optional[str] = None
    tunnel_name: Optional[str] = None
    vrf: str = "0"
    raw_line: str = ""


class FortinetRoutingParser:
    """
    Parser for Fortinet FortiGate routing table output.

    Parses output from: get router info routing-table all

    Example output:
    Routing table for VRF=0
    S*      0.0.0.0/0 [10/0] via 192.168.100.1, port1, [1/0]
    S       10.5.0.0/16 [10/0] via 192.168.200.65, port2, [1/0]
    B       10.10.0.0/16 [200/0] via 10.100.1.3 (recursive via DeemJeddah tunnel 10.100.1.3), 01w3d22h, [1/0]
    C       192.168.100.0/24 is directly connected, port1
    """

    # Route type codes
    ROUTE_CODES = {
        'K': 'K',   # kernel
        'C': 'C',   # connected
        'S': 'S',   # static
        'R': 'R',   # RIP
        'B': 'B',   # BGP
        'O': 'O',   # OSPF
        'IA': 'IA', # OSPF inter area
        'N1': 'N1', # OSPF NSSA external type 1
        'N2': 'N2', # OSPF NSSA external type 2
        'E1': 'E1', # OSPF external type 1
        'E2': 'E2', # OSPF external type 2
        'i': 'i',   # IS-IS
        'L1': 'L1', # IS-IS level-1
        'L2': 'L2', # IS-IS level-2
        'ia': 'ia', # IS-IS inter area
        'V': 'V',   # BGP VPNv4
    }

    # Pattern for standard route line
    # S*      0.0.0.0/0 [10/0] via 192.168.100.1, port1, [1/0]
    ROUTE_PATTERN = re.compile(
        r'^(?P<type>[A-Za-z*]+)\s+'  # Route type (may include *)
        r'(?P<network>\d+\.\d+\.\d+\.\d+/\d+)\s+'  # Network/prefix
        r'\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+'  # [AD/metric]
        r'via\s+(?P<next_hop>[\d\.]+)'  # via next-hop
        r'(?:\s+\(recursive[^)]+\))?'  # optional (recursive via...)
        r'(?:,\s+(?P<interface>\S+))?'  # optional interface
        r'(?:.*\[(?P<pref>\d+/\d+)\])?'  # optional [pref]
    )

    # Pattern for connected routes
    # C       192.168.100.0/24 is directly connected, port1
    CONNECTED_PATTERN = re.compile(
        r'^(?P<type>[C])\s+'
        r'(?P<network>\d+\.\d+\.\d+\.\d+/\d+)\s+'
        r'is directly connected,\s*(?P<interface>\S+)'
    )

    # Pattern for recursive routes with tunnel
    # B       10.10.0.0/16 [200/0] via 10.100.1.3 (recursive via DeemJeddah tunnel 10.100.1.3), 01w3d22h, [1/0]
    RECURSIVE_PATTERN = re.compile(
        r'^\s*\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+'
        r'via\s+(?P<next_hop>[\d\.]+)\s+'
        r'\(recursive[^,]+,\s*(?P<tunnel>\S+)\)'
    )

    # VRF header pattern
    VRF_PATTERN = re.compile(r'Routing table for VRF=(\d+)')

    @classmethod
    def parse(cls, raw_output: str) -> List[ParsedRoute]:
        """
        Parse Fortinet routing table output.
        Returns list of ParsedRoute objects.
        """
        routes = []
        current_vrf = "0"
        current_route: Optional[ParsedRoute] = None

        lines = raw_output.split('\n')

        for line_num, line in enumerate(lines):
            line = line.rstrip()

            # Skip empty lines and headers
            if not line or line.startswith('Codes:') or line.startswith('       '):
                # Check if this is a continuation line for multi-path routes
                if line.strip().startswith('[') and current_route:
                    # Multi-path continuation - add as additional route
                    new_route = cls._parse_continuation_line(line, current_route)
                    if new_route:
                        routes.append(new_route)
                continue

            # Check for VRF header
            vrf_match = cls.VRF_PATTERN.search(line)
            if vrf_match:
                current_vrf = vrf_match.group(1)
                continue

            # Skip command echo and prompts
            if 'get router' in line.lower() or line.endswith('#') or line.endswith('$'):
                continue

            # Try to parse as a route
            parsed = cls._parse_route_line(line, current_vrf)
            if parsed:
                routes.append(parsed)
                current_route = parsed

        logger.info(f"Parsed {len(routes)} routes from Fortinet output")
        return routes

    @classmethod
    def _parse_route_line(cls, line: str, vrf: str) -> Optional[ParsedRoute]:
        """Parse a single route line."""
        line = line.strip()

        # Try connected route pattern first
        match = cls.CONNECTED_PATTERN.match(line)
        if match:
            network = match.group('network')
            prefix_len = int(network.split('/')[1])
            return ParsedRoute(
                route_type='C',
                network=network,
                prefix_length=prefix_len,
                interface=match.group('interface'),
                vrf=vrf,
                raw_line=line,
                is_default=(network == '0.0.0.0/0')
            )

        # Parse standard route with via
        # Match pattern: TYPE NETWORK [AD/METRIC] via NEXTHOP...
        standard_match = re.match(
            r'^([A-Za-z*]+)\s+'  # Type
            r'(\d+\.\d+\.\d+\.\d+/\d+)\s+'  # Network
            r'\[(\d+)/(\d+)\]\s+'  # AD/Metric
            r'via\s+([\d\.]+)'  # Next hop
            r'(.*)$',  # Rest of line
            line
        )

        if standard_match:
            route_type_raw = standard_match.group(1)
            network = standard_match.group(2)
            ad = int(standard_match.group(3))
            metric = int(standard_match.group(4))
            next_hop = standard_match.group(5)
            rest = standard_match.group(6)

            # Clean route type (remove * for default)
            is_default = '*' in route_type_raw
            route_type = route_type_raw.replace('*', '')

            # Parse interface from rest
            interface = None
            tunnel_name = None
            is_recursive = False
            recursive_via = None
            age = None
            preference = None

            # Check for recursive route
            recursive_match = re.search(r'\(recursive via (\S+)\s+tunnel\s+(\S+)\)', rest)
            if recursive_match:
                is_recursive = True
                recursive_via = recursive_match.group(1)
                tunnel_name = recursive_match.group(2)

            recursive_match2 = re.search(r'\(recursive is directly connected,\s*(\S+)\)', rest)
            if recursive_match2:
                is_recursive = True
                interface = recursive_match2.group(1)

            # Extract interface
            interface_match = re.search(r',\s*([a-zA-Z0-9\-_]+\d*),', rest)
            if interface_match and not interface:
                interface = interface_match.group(1)

            # Extract age
            age_match = re.search(r',\s*(\d+[wdhms][^,]*),', rest)
            if age_match:
                age = age_match.group(1)

            # Extract preference
            pref_match = re.search(r'\[(\d+/\d+)\]\s*$', rest)
            if pref_match:
                preference = pref_match.group(1)

            prefix_len = int(network.split('/')[1])

            return ParsedRoute(
                route_type=route_type,
                network=network,
                prefix_length=prefix_len,
                next_hop=next_hop,
                interface=interface,
                admin_distance=ad,
                metric=metric,
                preference=preference,
                age=age,
                is_default=is_default or (network == '0.0.0.0/0'),
                is_recursive=is_recursive,
                recursive_via=recursive_via,
                tunnel_name=tunnel_name,
                vrf=vrf,
                raw_line=line
            )

        return None

    @classmethod
    def _parse_continuation_line(
        cls,
        line: str,
        base_route: ParsedRoute
    ) -> Optional[ParsedRoute]:
        """Parse a continuation line for multi-path routes."""
        line = line.strip()

        # Match: [AD/METRIC] via NEXTHOP (recursive...)
        match = re.match(
            r'\[(\d+)/(\d+)\]\s+via\s+([\d\.]+)\s*(.*)$',
            line
        )

        if match:
            ad = int(match.group(1))
            metric = int(match.group(2))
            next_hop = match.group(3)
            rest = match.group(4)

            # Check for recursive info
            is_recursive = False
            recursive_via = None
            tunnel_name = None
            interface = None

            recursive_match = re.search(r'\(recursive via (\S+)\s+tunnel\s+(\S+)\)', rest)
            if recursive_match:
                is_recursive = True
                recursive_via = recursive_match.group(1)
                tunnel_name = recursive_match.group(2)

            recursive_match2 = re.search(r'\(recursive is directly connected,\s*(\S+)\)', rest)
            if recursive_match2:
                is_recursive = True
                interface = recursive_match2.group(1)

            return ParsedRoute(
                route_type=base_route.route_type,
                network=base_route.network,
                prefix_length=base_route.prefix_length,
                next_hop=next_hop,
                interface=interface or base_route.interface,
                admin_distance=ad,
                metric=metric,
                is_default=base_route.is_default,
                is_recursive=is_recursive,
                recursive_via=recursive_via,
                tunnel_name=tunnel_name,
                vrf=base_route.vrf,
                raw_line=line
            )

        return None


class PaloAltoRoutingParser:
    """
    Parser for Palo Alto Networks (PAN-OS) routing table output.

    Parses output from the operational command `show routing route`. The PAN-OS
    output uses a flag-letter scheme rather than left-hand route-type letters;
    flags are documented in the table header (CLI Quick Start, "show routing").

    Example::

        flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal,
               R:rip, O:ospf, B:bgp, Oi:ospf intra-area, Oo:ospf inter-area,
               O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast

        VIRTUAL ROUTER: default (id 1)
        ==========
        destination       nexthop          metric flags age   interface       next-AS
        0.0.0.0/0         10.0.0.1         10     A S       ethernet1/1
        10.0.0.0/24       0.0.0.0          0      A C   ?     ethernet1/1
        172.16.0.0/16     10.10.10.2       110    A Oo  3d    tunnel.1        65000
    """

    # Order matters: longer flag tokens (Oi/Oo/O1/O2) must be matched before
    # the single-letter ones (O), so we test multi-char codes first.
    _MULTI_FLAG_CODES = ['Oi', 'Oo', 'O1', 'O2']
    _FLAG_TO_TYPE = {
        'C': 'C',   # connected
        'S': 'S',   # static
        'R': 'R',   # rip
        'O': 'O',   # ospf
        'Oi': 'IA', # OSPF intra-area  -> map to closest existing RouteType
        'Oo': 'IA', # OSPF inter-area
        'O1': 'E1', # OSPF external type 1
        'O2': 'E2', # OSPF external type 2
        'B': 'B',   # bgp
        'H': 'C',   # host route — treat like connected
    }

    VR_HEADER_RE = re.compile(r'^VIRTUAL\s+ROUTER:\s+(?P<name>\S+)', re.IGNORECASE)
    HEADER_LINE_RE = re.compile(r'^\s*destination\s+nexthop\b', re.IGNORECASE)
    NETWORK_RE = re.compile(r'^(?P<network>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b')
    IPV6_NETWORK_RE = re.compile(r'^(?P<network>[0-9a-fA-F:]+/\d{1,3})\b')
    IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

    @classmethod
    def _classify_route_type(cls, flag_token: str) -> str:
        """Pick the most informative protocol code from a flag bundle.

        PAN-OS prints flags concatenated like ``A C`` or ``A B Oi``. ``A``
        means active and is informational, not a protocol; we strip it and
        return the first protocol code we recognise."""
        if not flag_token:
            return 'S'
        # Drop separators and 'A' (active) / '?' (loose) / '~' (internal) / 'M' / 'E' which are not protocols.
        cleaned = re.sub(r'[A?~ME]', '', flag_token)
        # First try multi-char codes, then single-letter.
        for code in cls._MULTI_FLAG_CODES:
            if code in cleaned:
                return cls._FLAG_TO_TYPE[code]
        for ch in cleaned:
            mapped = cls._FLAG_TO_TYPE.get(ch)
            if mapped:
                return mapped
        return 'S'  # fallback to Static when the protocol can't be determined

    @classmethod
    def parse(cls, raw_output: str) -> List[ParsedRoute]:
        """Parse PAN-OS show routing route output into ParsedRoute objects."""
        routes: List[ParsedRoute] = []
        if not raw_output:
            return routes

        current_vr = '0'
        in_table = False  # True after we've seen the column header for the current VR

        for raw_line in raw_output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                in_table = False
                continue

            vr_match = cls.VR_HEADER_RE.match(line.strip())
            if vr_match:
                current_vr = vr_match.group('name')
                in_table = False
                continue

            if cls.HEADER_LINE_RE.match(line):
                in_table = True
                continue

            if not in_table:
                continue

            # Skip separator lines like '======' or 'flags:' continuation.
            if set(line.strip()) <= {'='}:
                continue
            if line.strip().lower().startswith(('flags:', 'codes:', 'total ')):
                continue

            tokens = line.split()
            net_match = cls.NETWORK_RE.match(tokens[0]) or cls.IPV6_NETWORK_RE.match(tokens[0])
            if not net_match or len(tokens) < 4:
                continue

            network_full = net_match.group('network')
            if '/' in network_full:
                network, prefix_str = network_full.split('/', 1)
                try:
                    prefix_length = int(prefix_str)
                except ValueError:
                    continue
            else:
                network, prefix_length = network_full, 32

            next_hop_tok = tokens[1]
            next_hop = next_hop_tok if cls.IPV4_RE.match(next_hop_tok) else None
            try:
                metric = int(tokens[2])
            except (ValueError, IndexError):
                metric = None

            # Flags can span multiple tokens (e.g. `A C` or `A B Oi`). The next
            # numeric/age token closes the flag run; everything between the
            # metric and that boundary is treated as flag characters.
            flag_tokens: List[str] = []
            cursor = 3
            while cursor < len(tokens):
                t = tokens[cursor]
                # Age is an alnum token (e.g. '3d', '1d 02:30:00', '?')
                # Interface starts with eth/ae/tunnel/loopback/vlan/sub.
                if t.lower().startswith(('ethernet', 'ae', 'tunnel', 'loopback', 'vlan', 'sub')):
                    break
                if re.match(r'^\d+(?:[dhwms]|:\d+)', t):
                    break
                if t == '?' or len(t) <= 3 and re.match(r'^[A-Za-z?~]+$', t):
                    flag_tokens.append(t)
                    cursor += 1
                else:
                    break
            flags = ''.join(flag_tokens)
            route_type = cls._classify_route_type(flags)

            # Optional age token (skip if matched a number/letter unit).
            age = None
            if cursor < len(tokens) and re.match(r'^\d+(?:[dhwms]|:\d+)', tokens[cursor]):
                age = tokens[cursor]
                cursor += 1

            interface = None
            if cursor < len(tokens) and not cls.IPV4_RE.match(tokens[cursor]):
                interface = tokens[cursor]
                cursor += 1

            is_default = network == '0.0.0.0' and prefix_length == 0
            routes.append(ParsedRoute(
                route_type=route_type,
                network=network_full,
                prefix_length=prefix_length,
                next_hop=next_hop,
                interface=interface,
                metric=metric,
                age=age,
                is_default=is_default,
                vrf=current_vr,
                raw_line=raw_line,
            ))

        return routes


class RoutingTableParser:
    """Generic routing table parser - selects appropriate parser based on device type."""

    PARSERS = {
        'FORTINET': FortinetRoutingParser,
        'PALOALTO': PaloAltoRoutingParser,
    }

    @classmethod
    def parse(cls, raw_output: str, device_type: str = 'FORTINET') -> List[ParsedRoute]:
        """Parse routing table using appropriate parser for device type."""
        parser_class = cls.PARSERS.get(device_type.upper())
        if not parser_class:
            logger.warning(f"No parser for device type: {device_type}, using Fortinet parser")
            parser_class = FortinetRoutingParser

        return parser_class.parse(raw_output)

    @classmethod
    def get_route_summary(cls, routes: List[ParsedRoute]) -> Dict:
        """Get summary statistics for parsed routes."""
        summary = {
            'total': len(routes),
            'by_type': {},
            'default_routes': 0,
            'recursive_routes': 0,
            'unique_next_hops': set(),
            'unique_interfaces': set(),
        }

        for route in routes:
            # Count by type
            rt = route.route_type
            summary['by_type'][rt] = summary['by_type'].get(rt, 0) + 1

            # Count defaults
            if route.is_default:
                summary['default_routes'] += 1

            # Count recursive
            if route.is_recursive:
                summary['recursive_routes'] += 1

            # Collect unique next hops and interfaces
            if route.next_hop:
                summary['unique_next_hops'].add(route.next_hop)
            if route.interface:
                summary['unique_interfaces'].add(route.interface)

        # Convert sets to counts
        summary['unique_next_hops'] = len(summary['unique_next_hops'])
        summary['unique_interfaces'] = len(summary['unique_interfaces'])

        return summary
