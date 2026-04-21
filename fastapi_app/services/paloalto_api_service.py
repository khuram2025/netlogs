"""
Palo Alto Networks (PAN-OS) XML API client.

Read-only fetcher for the firewall rule base + address/service objects
via the PAN-OS XML API. Emits the same ``Parsed*`` dataclasses as the
Fortinet API client so downstream services (FirewallPolicyService, the
Policy Lookup match engine) don't care which vendor produced them.

Supported auth modes:
- Pre-issued API key in ``credential.password`` (recommended; PA admins
  generate these with ``GET /api/?type=keygen&user=...&password=...``
  once and paste the resulting key).
- Username + password; the client will call ``keygen`` itself and cache
  the resulting key for the lifetime of this object.

Scope (MVP): single-firewall NGFW with one or more vsys. Panorama device
groups and post-rulebase are not yet covered — that would need a separate
client flow because the xpath and rule-ordering semantics differ.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import httpx

from .firewall_policy_parser import (
    ParsedAddress, ParsedPolicy, ParsedService, ParsedFirewallConfig,
)

logger = logging.getLogger(__name__)


class PaloAltoAPIError(Exception):
    """Raised when the PAN-OS XML API returns an error or is unreachable."""


def _members(entry: ET.Element, tag: str) -> List[str]:
    """Return ``<member>`` text values inside ``<tag>``. Missing → []."""
    container = entry.find(tag)
    if container is None:
        return []
    return [(m.text or "").strip() for m in container.findall("member") if m.text]


def _text(entry: ET.Element, path: str, default: Optional[str] = None) -> Optional[str]:
    """Return the text of the first matching child, or default."""
    node = entry.find(path)
    if node is None or node.text is None:
        return default
    v = node.text.strip()
    return v or default


class PaloAltoAPIClient:
    """Thin wrapper over the PAN-OS XML API."""

    # Default firewall config root. Panorama would use ``/config/panorama``
    # plus device-groups; we take the firewall path here.
    _FIREWALL_DEVICE = "localhost.localdomain"

    def __init__(
        self,
        host: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_tls: bool = False,
        timeout: float = 30.0,
    ):
        if not api_key and not (username and password):
            raise PaloAltoAPIError(
                "PAN-OS API needs either an api_key or (username, password)"
            )
        self.base_url = f"https://{host}:{port}"
        self._cached_key: Optional[str] = api_key
        self._username = username
        self._password = password
        self.timeout = timeout
        self.verify_tls = verify_tls

    # ── transport ──────────────────────────────────────────────────

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            verify=self.verify_tls,
        )

    def _api(self, params: Dict[str, Any]) -> ET.Element:
        """Issue a request and return the ``<response>`` root element.

        Raises ``PaloAltoAPIError`` on transport error, non-2xx response,
        malformed XML, or an XML ``status="error"`` payload.
        """
        with self._client() as c:
            try:
                resp = c.get("/api/", params=params)
            except httpx.HTTPError as e:
                raise PaloAltoAPIError(f"network error: {e}") from e
        if resp.status_code == 401:
            raise PaloAltoAPIError("Authentication failed (HTTP 401) — check credentials")
        if resp.status_code == 403:
            raise PaloAltoAPIError("Forbidden (HTTP 403) — API role lacks permission")
        if resp.status_code >= 400:
            snippet = (resp.text or "")[:200]
            raise PaloAltoAPIError(f"HTTP {resp.status_code}: {snippet}")
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            raise PaloAltoAPIError(f"malformed XML: {e}") from e
        status = (root.get("status") or "").lower()
        if status == "error":
            # PAN-OS error payloads vary; gather anything useful.
            msg_parts: List[str] = []
            for m in root.iter():
                if m.tag in ("msg", "line") and m.text:
                    msg_parts.append(m.text.strip())
            msg = " ".join(msg_parts) or (resp.text[:200] if resp.text else "unknown")
            raise PaloAltoAPIError(f"API error: {msg}")
        return root

    # ── key handling ───────────────────────────────────────────────

    def _api_key(self) -> str:
        if self._cached_key:
            return self._cached_key
        if not (self._username and self._password):
            raise PaloAltoAPIError("No API key and no username/password for keygen")
        root = self._api({
            "type": "keygen",
            "user": self._username,
            "password": self._password,
        })
        key = None
        node = root.find(".//key")
        if node is not None and node.text:
            key = node.text.strip()
        if not key:
            raise PaloAltoAPIError("keygen returned no <key>")
        self._cached_key = key
        return key

    def _get(self, xpath: str) -> ET.Element:
        """Issue a config-get for ``xpath`` and return the ``<result>`` node."""
        root = self._api({
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self._api_key(),
        })
        result = root.find("result")
        if result is None:
            raise PaloAltoAPIError("response missing <result>")
        return result

    @staticmethod
    def _entries_from_result(result: ET.Element, container_tag: str) -> List[ET.Element]:
        """Pull direct ``<entry>`` children from a PAN-OS ``<result>``.

        PAN-OS wraps list results in the object-type container (e.g.
        ``<address>``) when the xpath points to that node. When the xpath
        resolves to a specific entry, ``<result>`` contains just
        ``<entry>`` directly. Handle both shapes.
        """
        container = result.find(container_tag)
        if container is not None:
            parent = container
        else:
            parent = result
        return [e for e in list(parent) if e.tag == "entry"]

    # ── xpath helpers ──────────────────────────────────────────────

    @classmethod
    def _vsys_xpath(cls, vsys: str, leaf: str) -> str:
        return (
            f"/config/devices/entry[@name='{cls._FIREWALL_DEVICE}']"
            f"/vsys/entry[@name='{vsys}']/{leaf}"
        )

    @classmethod
    def _shared_xpath(cls, leaf: str) -> str:
        return f"/config/shared/{leaf}"

    @classmethod
    def _panorama_vsys_xpath(cls, vsys: str, leaf: str) -> str:
        """Config path for Panorama-pushed objects on a managed firewall.

        When a PAN-OS firewall is Panorama-managed, the committed push
        lives under ``/config/panorama/vsys/entry[@name=VSYS]/…`` on the
        firewall itself — ``pre-rulebase`` / ``post-rulebase`` for
        security rules, plus ``address``, ``address-group``, ``service``,
        ``service-group`` for pushed objects. The web UI reads this path
        alongside the local vsys config, which is why a managed firewall
        can show hundreds of rules while the local rulebase only has
        whatever the local admin wrote.

        On a non-managed firewall this xpath returns an empty ``<result>``
        — safe to call unconditionally.
        """
        return f"/config/panorama/vsys/entry[@name='{vsys}']/{leaf}"

    # ── connectivity ───────────────────────────────────────────────

    def system_info(self) -> Dict[str, str]:
        """Operational ``show system info`` — reachability + auth probe."""
        root = self._api({
            "type": "op", "cmd": "<show><system><info/></system></show>",
            "key": self._api_key(),
        })
        info: Dict[str, str] = {}
        result = root.find("result/system")
        if result is None:
            return info
        for child in result:
            if child.text:
                info[child.tag] = child.text.strip()
        return info

    def list_vdoms(self) -> List[str]:
        """Return configured vsys names (maps to FortiGate 'VDOM' slot)."""
        try:
            result = self._get(
                f"/config/devices/entry[@name='{self._FIREWALL_DEVICE}']/vsys"
            )
        except PaloAltoAPIError:
            return []
        names: List[str] = []
        for entry in result.iter("entry"):
            n = entry.get("name")
            if n:
                names.append(n)
        return names

    # ── address objects ────────────────────────────────────────────

    @staticmethod
    def _parse_address_entry(entry: ET.Element) -> ParsedAddress:
        name = entry.get("name") or ""
        ip_netmask = _text(entry, "ip-netmask")
        ip_range = _text(entry, "ip-range")
        fqdn = _text(entry, "fqdn")
        ip_wildcard = _text(entry, "ip-wildcard")
        if ip_netmask:
            # PAN-OS stores as CIDR ("10.0.0.0/24") or bare host IP.
            # Translate to the "address netmask" form the rest of the
            # stack expects, so the match engine's _parse_ipmask works
            # without vendor branches.
            if "/" in ip_netmask:
                ip, prefix = ip_netmask.split("/", 1)
                try:
                    import ipaddress
                    nw = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                    value = f"{ip} {nw.netmask}"
                except ValueError:
                    value = ip_netmask
            else:
                value = f"{ip_netmask} 255.255.255.255"
            kind = "ipmask"
        elif ip_range:
            kind = "iprange"
            value = ip_range
        elif fqdn:
            kind = "fqdn"
            value = fqdn
        elif ip_wildcard:
            # Rare; store raw. Match engine will fall back to literal parse
            # which usually fails on wildcards — treat as unsupported.
            kind = "dynamic"
            value = ip_wildcard
        else:
            kind = "ipmask"
            value = None
        return ParsedAddress(
            name=name, kind=kind, value=value,
            comment=_text(entry, "description"),
            raw_definition=ET.tostring(entry, encoding="unicode"),
        )

    def _object_xpaths(self, vsys: str, leaf: str) -> List[str]:
        """All xpaths we poll for a given object type, ordered low→high
        priority so later entries win on name collision when we de-dupe.

        Order: shared → Panorama-pushed → local vsys.
        - Shared lives at ``/config/shared/LEAF`` on both standalone and
          Panorama-managed firewalls.
        - Panorama-pushed objects land in ``/config/panorama/vsys/…`` on
          a managed firewall.
        - Local vsys is the admin-defined layer and should override.
        """
        return [
            self._shared_xpath(leaf),
            self._panorama_vsys_xpath(vsys, leaf),
            self._vsys_xpath(vsys, leaf),
        ]

    def addresses(self, vsys: str) -> List[ParsedAddress]:
        out: List[ParsedAddress] = []
        for xp in self._object_xpaths(vsys, "address"):
            try:
                result = self._get(xp)
            except PaloAltoAPIError as e:
                logger.debug(f"PAN-OS addresses {xp}: {e}")
                continue
            for entry in self._entries_from_result(result, "address"):
                out.append(self._parse_address_entry(entry))
        # De-dupe by name — higher-priority layers (later in the list)
        # overwrite lower ones.
        dedup: Dict[str, ParsedAddress] = {}
        for a in out:
            if a.name:
                dedup[a.name] = a
        return list(dedup.values())

    def address_groups(self, vsys: str) -> List[ParsedAddress]:
        out: List[ParsedAddress] = []
        for xp in self._object_xpaths(vsys, "address-group"):
            try:
                result = self._get(xp)
            except PaloAltoAPIError as e:
                logger.debug(f"PAN-OS address-groups {xp}: {e}")
                continue
            for entry in self._entries_from_result(result, "address-group"):
                members = _members(entry, "static")
                if not members:
                    # Dynamic groups use a tag filter; we store raw for audit
                    # but no expandable member list.
                    members = _members(entry, "dynamic")
                out.append(ParsedAddress(
                    name=entry.get("name") or "", kind="group",
                    members=members,
                    comment=_text(entry, "description"),
                    raw_definition=ET.tostring(entry, encoding="unicode"),
                ))
        dedup: Dict[str, ParsedAddress] = {}
        for a in out:
            if a.name:
                dedup[a.name] = a
        return list(dedup.values())

    # ── service objects ────────────────────────────────────────────

    @staticmethod
    def _parse_service_entry(entry: ET.Element) -> ParsedService:
        name = entry.get("name") or ""
        proto_node = entry.find("protocol")
        proto = "tcp"
        ports = None
        if proto_node is not None:
            tcp = proto_node.find("tcp")
            udp = proto_node.find("udp")
            if tcp is not None and udp is not None:
                t_ports = _text(tcp, "port")
                u_ports = _text(udp, "port")
                proto = "tcp_udp"
                ports = f"tcp:{t_ports or ''} udp:{u_ports or ''}".strip()
            elif tcp is not None:
                proto = "tcp"
                ports = _text(tcp, "port")
            elif udp is not None:
                proto = "udp"
                ports = _text(udp, "port")
            elif proto_node.find("sctp") is not None:
                proto = "sctp"
                ports = _text(proto_node.find("sctp"), "port")
        return ParsedService(
            name=name, protocol=proto, ports=ports,
            category=_text(entry, "tag"),
            comment=_text(entry, "description"),
            raw_definition=ET.tostring(entry, encoding="unicode"),
        )

    def services(self, vsys: str) -> List[ParsedService]:
        out: List[ParsedService] = []
        for xp in self._object_xpaths(vsys, "service"):
            try:
                result = self._get(xp)
            except PaloAltoAPIError as e:
                logger.debug(f"PAN-OS services {xp}: {e}")
                continue
            for entry in self._entries_from_result(result, "service"):
                out.append(self._parse_service_entry(entry))
        dedup: Dict[str, ParsedService] = {}
        for s in out:
            if s.name:
                dedup[s.name] = s
        return list(dedup.values())

    def service_groups(self, vsys: str) -> List[ParsedService]:
        out: List[ParsedService] = []
        for xp in self._object_xpaths(vsys, "service-group"):
            try:
                result = self._get(xp)
            except PaloAltoAPIError as e:
                logger.debug(f"PAN-OS service-groups {xp}: {e}")
                continue
            for entry in self._entries_from_result(result, "service-group"):
                out.append(ParsedService(
                    name=entry.get("name") or "", protocol="group",
                    members=_members(entry, "members"),
                    comment=_text(entry, "description"),
                    raw_definition=ET.tostring(entry, encoding="unicode"),
                ))
        dedup: Dict[str, ParsedService] = {}
        for s in out:
            if s.name:
                dedup[s.name] = s
        return list(dedup.values())

    # ── security rules ─────────────────────────────────────────────

    @staticmethod
    def _parse_rule_entry(entry: ET.Element, position: int) -> ParsedPolicy:
        action = (_text(entry, "action") or "allow").lower()
        # PAN-OS actions: allow, deny, drop, reset-client, reset-server,
        # reset-both. Normalise "allow" → "accept" so downstream code that
        # only checks for "accept"/"deny" is consistent across vendors.
        if action == "allow":
            action = "accept"
        elif action in ("drop", "reset-client", "reset-server", "reset-both"):
            action = "deny"

        disabled = (_text(entry, "disabled") or "no").lower()
        name = entry.get("name") or f"rule-{position}"

        return ParsedPolicy(
            rule_id=name,          # PAN rules are keyed by name, not int id
            name=name,
            position=position,
            enabled=(disabled != "yes"),
            action=action,
            src_zones=_members(entry, "from"),
            dst_zones=_members(entry, "to"),
            src_addresses=_members(entry, "source"),
            dst_addresses=_members(entry, "destination"),
            services=_members(entry, "service"),
            applications=_members(entry, "application"),
            users=_members(entry, "source-user"),
            # PAN rules don't toggle NAT inside security policy; NAT lives
            # in a separate rulebase. Leave False for now.
            nat_enabled=False,
            log_traffic=_text(entry, "log-setting"),
            schedule=_text(entry, "schedule"),
            comment=_text(entry, "description"),
            raw_definition=ET.tostring(entry, encoding="unicode"),
        )

    def _rules_at(self, xpath: str) -> List[ET.Element]:
        """Fetch an xpath and return its ``<entry>`` children.

        Returns [] when the xpath has no rules or isn't configured (common
        for non-Panorama firewalls querying ``/config/panorama/…``).
        """
        try:
            result = self._get(xpath)
        except PaloAltoAPIError as e:
            logger.debug(f"PAN-OS rules {xpath}: {e}")
            return []
        return self._entries_from_result(result, "rules")

    def policies(self, vsys: str) -> List[ParsedPolicy]:
        """Return security rules in firewall evaluation order.

        PAN-OS evaluates (top→bottom):
            1. Panorama pre-rulebase  — pushed from Panorama, highest priority
            2. Local vsys rulebase    — whatever the firewall admin wrote
            3. Panorama post-rulebase — pushed from Panorama, lowest priority

        We concatenate in that order and assign a contiguous ``position``
        1..N so the match engine's first-match-wins behaviour mirrors the
        firewall dataplane. On a non-managed firewall the pre/post lookups
        return [] and we just get the local vsys rules.
        """
        pre = self._rules_at(
            self._panorama_vsys_xpath(vsys, "pre-rulebase/security/rules")
        )
        local = self._rules_at(
            self._vsys_xpath(vsys, "rulebase/security/rules")
        )
        post = self._rules_at(
            self._panorama_vsys_xpath(vsys, "post-rulebase/security/rules")
        )

        out: List[ParsedPolicy] = []
        position = 0
        for entry in pre + local + post:
            position += 1
            out.append(self._parse_rule_entry(entry, position))
        return out

    # ── bundle ─────────────────────────────────────────────────────

    def fetch_policy_bundle(
        self, vdom: Optional[str] = None,
    ) -> ParsedFirewallConfig:
        """Pull everything in one call. ``vdom`` is the vsys name; defaults to ``vsys1``."""
        vsys = vdom or "vsys1"
        cfg = ParsedFirewallConfig()
        cfg.addresses = self.addresses(vsys)
        cfg.address_groups = self.address_groups(vsys)
        cfg.services = self.services(vsys)
        cfg.service_groups = self.service_groups(vsys)
        cfg.policies = self.policies(vsys)
        return cfg
