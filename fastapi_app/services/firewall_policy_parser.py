"""
FortiGate firewall-policy + objects parser.

Parses the textual config blocks emitted by:

  show firewall address          → address objects (subnet/range/fqdn/etc.)
  show firewall addrgrp          → address groups
  show firewall service custom   → service objects (tcp-portrange, udp-portrange…)
  show firewall service group    → service groups
  show firewall policy           → security rules

All five share FortiOS's uniform block syntax::

    config firewall address
        edit "Internal_DNS"
            set type ipmask
            set subnet 10.10.10.10 255.255.255.255
        next
        edit "ServerSubnet"
            set type ipmask
            set subnet 10.20.0.0 255.255.0.0
        next
    end

Lists are space-separated quoted tokens, e.g.::

    set srcaddr "Internal_DNS" "ServerSubnet"
    set service "HTTPS" "DNS"

The parser returns dataclasses that map 1:1 to the model rows in
`models/firewall_policy.py`.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedAddress:
    name: str
    kind: str = "ipmask"        # ipmask | iprange | fqdn | geography | dynamic | group
    value: Optional[str] = None
    members: List[str] = field(default_factory=list)
    comment: Optional[str] = None
    raw_definition: str = ""


@dataclass
class ParsedService:
    name: str
    protocol: str = "tcp"       # tcp | udp | tcp_udp | icmp | ip | group
    ports: Optional[str] = None
    members: List[str] = field(default_factory=list)
    category: Optional[str] = None
    comment: Optional[str] = None
    raw_definition: str = ""


@dataclass
class ParsedPolicy:
    rule_id: Optional[str] = None
    name: Optional[str] = None
    position: int = 0
    enabled: bool = True
    action: str = "accept"
    src_zones: List[str] = field(default_factory=list)
    dst_zones: List[str] = field(default_factory=list)
    src_addresses: List[str] = field(default_factory=list)
    dst_addresses: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    nat_enabled: bool = False
    log_traffic: Optional[str] = None
    schedule: Optional[str] = None
    comment: Optional[str] = None
    raw_definition: str = ""


@dataclass
class ParsedFirewallConfig:
    addresses: List[ParsedAddress] = field(default_factory=list)
    address_groups: List[ParsedAddress] = field(default_factory=list)
    services: List[ParsedService] = field(default_factory=list)
    service_groups: List[ParsedService] = field(default_factory=list)
    policies: List[ParsedPolicy] = field(default_factory=list)


# Section headers we recognise. Anything else is skipped.
_SECTION_RE = re.compile(
    r'^\s*config\s+firewall\s+(address|addrgrp|service\s+custom|service\s+group|policy)\s*$',
    re.IGNORECASE,
)

# `set key value` — value is the rest of the line after the key. May be
# either a quoted-token list, a single bareword, or a list of barewords.
_SET_RE = re.compile(r'^\s*set\s+(\S+)\s+(.*)$')

# `edit "name"` or `edit 12` (FortiGate uses unquoted ints for policy IDs).
_EDIT_RE = re.compile(r'^\s*edit\s+(?:"(?P<q>[^"]*)"|(?P<u>\S+))\s*$')


def _split_value_list(raw: str) -> List[str]:
    """
    Split a `set` value into its tokens.

    Handles quoted strings ("Internal DNS" "Web Server") and bare tokens
    (port-range, ICMP-Type, etc.) interchangeably.
    """
    if not raw:
        return []
    matches = re.findall(r'"([^"]*)"|(\S+)', raw)
    return [quoted or bare for quoted, bare in matches]


class FortinetFirewallConfigParser:
    """Stream parser for the combined `show firewall *` output."""

    @classmethod
    def parse(cls, raw_output: str) -> ParsedFirewallConfig:
        """
        Walk the SSH stream once, dispatching each `config firewall X` block
        to the appropriate sub-parser. Tolerant of interleaved prompts,
        banners, and the ANSI/CR junk paramiko captures alongside.
        """
        out = ParsedFirewallConfig()
        if not raw_output:
            return out

        # Strip CR / ANSI artefacts — they break the block delimiters when
        # captured from interactive shells (paramiko leaves \r and ESC[…m).
        cleaned = raw_output.replace("\r", "")
        cleaned = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', cleaned)
        lines = cleaned.splitlines()

        i = 0
        position_counter = 0  # for security policies: their order in the file
        while i < len(lines):
            m = _SECTION_RE.match(lines[i])
            if not m:
                i += 1
                continue

            section = re.sub(r'\s+', '_', m.group(1).lower())  # 'service custom' → 'service_custom'
            # Find the matching `end` to bound this block.
            block_start = i + 1
            block_end = block_start
            depth = 1
            while block_end < len(lines) and depth > 0:
                stripped = lines[block_end].strip().lower()
                if stripped.startswith('config '):
                    depth += 1
                elif stripped == 'end':
                    depth -= 1
                    if depth == 0:
                        break
                block_end += 1

            block_lines = lines[block_start:block_end]

            if section == 'address':
                out.addresses.extend(cls._parse_address_block(block_lines, group=False))
            elif section == 'addrgrp':
                out.address_groups.extend(cls._parse_address_block(block_lines, group=True))
            elif section == 'service_custom':
                out.services.extend(cls._parse_service_block(block_lines, group=False))
            elif section == 'service_group':
                out.service_groups.extend(cls._parse_service_block(block_lines, group=True))
            elif section == 'policy':
                policies, position_counter = cls._parse_policy_block(block_lines, position_counter)
                out.policies.extend(policies)

            i = block_end + 1

        return out

    # ── per-section sub-parsers ──────────────────────────────────────

    @staticmethod
    def _iter_entries(lines: List[str]):
        """Yield (name, [setlines], raw_block) for each `edit … next` entry."""
        i = 0
        while i < len(lines):
            m = _EDIT_RE.match(lines[i])
            if not m:
                i += 1
                continue
            name = m.group('q') or m.group('u')
            entry_lines: List[str] = []
            j = i + 1
            while j < len(lines):
                stripped = lines[j].strip()
                if stripped == 'next':
                    break
                entry_lines.append(lines[j])
                j += 1
            raw = "\n".join(lines[i:j + 1])
            yield name, entry_lines, raw
            i = j + 1

    @staticmethod
    def _set_value(setlines: List[str], key: str) -> Optional[str]:
        for ln in setlines:
            m = _SET_RE.match(ln)
            if m and m.group(1) == key:
                v = m.group(2).strip()
                # Unwrap a single double-quoted value if that's all there is.
                if len(v) >= 2 and v.startswith('"') and v.endswith('"') and v.count('"') == 2:
                    v = v[1:-1]
                return v
        return None

    @classmethod
    def _set_list(cls, setlines: List[str], key: str) -> List[str]:
        v = cls._set_value(setlines, key)
        return _split_value_list(v) if v else []

    @classmethod
    def _parse_address_block(cls, lines: List[str], group: bool) -> List[ParsedAddress]:
        out: List[ParsedAddress] = []
        for name, entry, raw in cls._iter_entries(lines):
            if group:
                addr = ParsedAddress(
                    name=name, kind='group',
                    members=cls._set_list(entry, 'member'),
                    comment=cls._set_value(entry, 'comment'),
                    raw_definition=raw,
                )
            else:
                kind = (cls._set_value(entry, 'type') or 'ipmask').lower()
                value = None
                if kind == 'ipmask':
                    subnet = cls._set_value(entry, 'subnet')
                    if subnet:
                        value = subnet  # e.g. "10.10.0.0 255.255.0.0"
                elif kind == 'iprange':
                    lo = cls._set_value(entry, 'start-ip')
                    hi = cls._set_value(entry, 'end-ip')
                    value = f"{lo}-{hi}" if lo and hi else None
                elif kind == 'fqdn':
                    value = cls._set_value(entry, 'fqdn')
                elif kind == 'geography':
                    value = cls._set_value(entry, 'country')
                else:
                    value = cls._set_value(entry, 'subnet') or cls._set_value(entry, 'fqdn')
                addr = ParsedAddress(
                    name=name, kind=kind, value=value,
                    comment=cls._set_value(entry, 'comment'),
                    raw_definition=raw,
                )
            out.append(addr)
        return out

    @classmethod
    def _parse_service_block(cls, lines: List[str], group: bool) -> List[ParsedService]:
        out: List[ParsedService] = []
        for name, entry, raw in cls._iter_entries(lines):
            if group:
                svc = ParsedService(
                    name=name, protocol='group',
                    members=cls._set_list(entry, 'member'),
                    comment=cls._set_value(entry, 'comment'),
                    raw_definition=raw,
                )
            else:
                proto_field = (cls._set_value(entry, 'protocol') or 'TCP/UDP/SCTP').upper()
                tcp_ports = cls._set_value(entry, 'tcp-portrange')
                udp_ports = cls._set_value(entry, 'udp-portrange')
                icmp_type = cls._set_value(entry, 'icmptype')
                if tcp_ports and udp_ports:
                    proto, ports = 'tcp_udp', f"tcp:{tcp_ports} udp:{udp_ports}"
                elif tcp_ports:
                    proto, ports = 'tcp', tcp_ports
                elif udp_ports:
                    proto, ports = 'udp', udp_ports
                elif icmp_type:
                    proto, ports = 'icmp', f"type:{icmp_type}"
                elif proto_field == 'IP':
                    proto = 'ip'
                    ports = cls._set_value(entry, 'protocol-number')
                else:
                    proto, ports = proto_field.lower(), None
                svc = ParsedService(
                    name=name, protocol=proto, ports=ports,
                    category=cls._set_value(entry, 'category'),
                    comment=cls._set_value(entry, 'comment'),
                    raw_definition=raw,
                )
            out.append(svc)
        return out

    @classmethod
    def _parse_policy_block(cls, lines: List[str], position_start: int):
        out: List[ParsedPolicy] = []
        position = position_start
        for name_or_id, entry, raw in cls._iter_entries(lines):
            position += 1
            action = (cls._set_value(entry, 'action') or 'accept').lower()
            # FortiGate uses `set status disable` to disable a rule.
            status = (cls._set_value(entry, 'status') or 'enable').lower()
            nat = (cls._set_value(entry, 'nat') or 'disable').lower() == 'enable'
            policy = ParsedPolicy(
                rule_id=name_or_id,                                 # numeric policyid
                name=cls._set_value(entry, 'name'),
                position=position,
                enabled=(status == 'enable'),
                action=action,
                src_zones=cls._set_list(entry, 'srcintf'),
                dst_zones=cls._set_list(entry, 'dstintf'),
                src_addresses=cls._set_list(entry, 'srcaddr'),
                dst_addresses=cls._set_list(entry, 'dstaddr'),
                services=cls._set_list(entry, 'service'),
                applications=cls._set_list(entry, 'application-list')
                              + cls._set_list(entry, 'application'),
                users=cls._set_list(entry, 'users') + cls._set_list(entry, 'groups'),
                nat_enabled=nat,
                log_traffic=cls._set_value(entry, 'logtraffic'),
                schedule=cls._set_value(entry, 'schedule'),
                comment=cls._set_value(entry, 'comments'),
                raw_definition=raw,
            )
            out.append(policy)
        return out, position


class FirewallConfigParser:
    """Vendor dispatcher (mirrors RoutingTableParser shape)."""

    PARSERS = {
        'FORTINET': FortinetFirewallConfigParser,
    }

    @classmethod
    def parse(cls, raw_output: str, device_type: str = 'FORTINET') -> ParsedFirewallConfig:
        parser_class = cls.PARSERS.get(device_type.upper())
        if not parser_class:
            logger.warning(f"No firewall-policy parser for device type: {device_type}")
            return ParsedFirewallConfig()
        return parser_class.parse(raw_output)
