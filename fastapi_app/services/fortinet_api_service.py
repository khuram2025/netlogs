"""
FortiGate REST API client.

Uses the FortiOS REST endpoints documented in the official FortiGate REST
API Guide. All read operations are GETs against
``https://<host>:<port>/api/v2/cmdb/firewall/...`` (config) or
``/api/v2/monitor/...`` (operational state). Authentication is a Bearer
token from a "REST API Admin" account on the device.

Returned objects map 1:1 to the same `Parsed*` dataclasses the SSH parsers
emit, so downstream services don't care which transport produced them.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .firewall_policy_parser import (
    ParsedAddress, ParsedService, ParsedPolicy, ParsedFirewallConfig,
)
from .routing_parser import ParsedRoute
from .zone_service import ParsedZone, ParsedInterface

logger = logging.getLogger(__name__)


class FortinetAPIError(Exception):
    """Raised when the FortiGate REST API returns an error or is unreachable."""


class FortinetAPIClient:
    """Thin wrapper around the FortiGate REST API.

    One short-lived client per fetch operation. We don't keep persistent
    sessions because token auth is stateless and reusing the same client
    across services that may run concurrently in different threads would
    only invite trouble.
    """

    def __init__(self, host: str, token: str, port: int = 443,
                 verify_tls: bool = False, timeout: float = 30.0):
        # Most FortiGates have a self-signed cert; verify_tls=False matches
        # the operator's expectation but should be flipped on per-device
        # later if/when a CA chain is configured.
        self.base_url = f"https://{host}:{port}"
        self.token = token
        self.timeout = timeout
        self.verify_tls = verify_tls

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            verify=self.verify_tls,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            },
        )

    # ── single GET helper ───────────────────────────────────────────

    def _get(self, path: str, vdom: Optional[str] = None,
             extra_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET path; raise FortiotinetAPIError on any non-2xx or auth fail."""
        params = dict(extra_params or {})
        if vdom:
            params["vdom"] = vdom
        with self._client() as c:
            try:
                resp = c.get(path, params=params)
            except httpx.HTTPError as e:
                raise FortinetAPIError(f"network error: {e}") from e
            if resp.status_code == 401:
                raise FortinetAPIError("Authentication failed (HTTP 401) — check API token")
            if resp.status_code == 403:
                raise FortinetAPIError("Forbidden (HTTP 403) — token lacks permission for this endpoint")
            if resp.status_code >= 400:
                snippet = (resp.text or "")[:200]
                raise FortinetAPIError(f"HTTP {resp.status_code}: {snippet}")
            try:
                return resp.json()
            except ValueError as e:
                raise FortinetAPIError(f"non-JSON response: {e}") from e

    # ── connectivity / health ───────────────────────────────────────

    def system_status(self) -> Dict[str, Any]:
        """Quick auth+reachability probe. Returns the raw status dict."""
        return self._get("/api/v2/monitor/system/status")

    # ── routing ─────────────────────────────────────────────────────

    @staticmethod
    def _route_type_from_proto(proto: str) -> str:
        # FortiGate monitor API returns "static", "connected", "bgp", "ospf"…
        m = {
            "connected": "C", "static": "S", "rip": "R", "bgp": "B",
            "ospf": "O", "isis": "i", "kernel": "K",
        }
        return m.get((proto or "").lower(), "S")

    def routing_table(self, vdom: Optional[str] = None) -> List[ParsedRoute]:
        """GET /api/v2/monitor/router/ipv4 → ParsedRoute objects.

        The monitor endpoint returns ``results: [{ip_mask, gateway, ...}]``
        already structured, so we don't need a CLI parser at all.
        """
        data = self._get("/api/v2/monitor/router/ipv4", vdom=vdom)
        out: List[ParsedRoute] = []
        for r in (data.get("results") or []):
            ip_mask = r.get("ip_mask") or r.get("ip") or ""
            if "/" in ip_mask:
                network, prefix = ip_mask.split("/", 1)
                try:
                    prefix_length = int(prefix)
                except ValueError:
                    continue
            else:
                network, prefix_length = ip_mask, 32
            out.append(ParsedRoute(
                route_type=self._route_type_from_proto(r.get("type") or r.get("install_type")),
                network=ip_mask,
                prefix_length=prefix_length,
                next_hop=r.get("gateway") or None,
                interface=r.get("interface") or None,
                metric=r.get("metric"),
                admin_distance=r.get("distance"),
                age=str(r.get("uptime") or "") or None,
                is_default=(network == "0.0.0.0" and prefix_length == 0),
                vrf=str(r.get("vrf") or "0"),
                raw_line=str(r),
            ))
        return out

    # ── zones / interfaces ──────────────────────────────────────────

    def zones_and_interfaces(
        self, vdom: Optional[str] = None,
    ) -> Tuple[List[ParsedZone], List[ParsedInterface]]:
        """Fetch zones + interfaces in two GETs and merge.

        FortiGate `firewall/zone` lists each zone's member interfaces.
        `system/interface` carries the IP / status / type per interface.
        """
        zones_resp = self._get("/api/v2/cmdb/system/zone", vdom=vdom)
        intf_resp = self._get("/api/v2/cmdb/system/interface", vdom=vdom)

        zones: List[ParsedZone] = []
        zone_lookup: Dict[str, str] = {}  # interface_name -> zone_name
        for z in (zones_resp.get("results") or []):
            members = [m.get("interface-name") or m.get("name")
                       for m in (z.get("interface") or [])
                       if (m.get("interface-name") or m.get("name"))]
            zones.append(ParsedZone(
                name=z.get("name") or "",
                description=z.get("description"),
                intrazone=(z.get("intrazone") or "deny").lower(),
                interfaces=members,
            ))
            for m in members:
                zone_lookup[m] = z.get("name") or ""

        interfaces: List[ParsedInterface] = []
        for i in (intf_resp.get("results") or []):
            name = i.get("name") or ""
            if not name:
                continue
            ip_field = i.get("ip") or ""  # often "10.0.0.1 255.255.255.0"
            ip_address = subnet_mask = subnet_cidr = None
            if isinstance(ip_field, str) and " " in ip_field:
                ip_address, subnet_mask = ip_field.split(" ", 1)
                try:
                    import ipaddress
                    nw = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
                    subnet_cidr = str(nw)
                except (ValueError, ipaddress.AddressValueError):
                    pass
            interfaces.append(ParsedInterface(
                name=name,
                ip_address=ip_address,
                subnet_mask=subnet_mask,
                subnet_cidr=subnet_cidr,
                interface_type=(i.get("type") or "").lower() or None,
                addressing_mode=(i.get("mode") or "").lower() or None,
                status=(i.get("status") or "up").lower(),
                zone_name=zone_lookup.get(name),
                vdom=i.get("vdom") or vdom,
            ))
        return zones, interfaces

    # ── firewall policy + objects ───────────────────────────────────

    @staticmethod
    def _names(items: Any) -> List[str]:
        """FortiGate references arrive as [{'name': 'X'}, …]."""
        if not items:
            return []
        if isinstance(items, list):
            return [str(x.get("name", "")) for x in items
                    if isinstance(x, dict) and x.get("name")]
        if isinstance(items, str):
            return [items]
        return []

    # FortiOS 7.x rejects cmdb/firewall/* calls without an explicit vdom
    # query param (HTTP 400) — even on single-VDOM boxes. The monitor and
    # system cmdb endpoints are more lenient, which is why routes/zones
    # worked but policy didn't. Default to "root" when no vdom is supplied.
    @staticmethod
    def _firewall_vdom(vdom: Optional[str]) -> str:
        return vdom or "root"

    def addresses(self, vdom: Optional[str] = None) -> List[ParsedAddress]:
        data = self._get("/api/v2/cmdb/firewall/address", vdom=self._firewall_vdom(vdom))
        out: List[ParsedAddress] = []
        for r in (data.get("results") or []):
            kind = (r.get("type") or "ipmask").lower()
            if kind == "ipmask":
                value = f"{r.get('subnet') or ''}".strip() or None
            elif kind == "iprange":
                value = f"{r.get('start-ip')}-{r.get('end-ip')}" \
                    if r.get("start-ip") and r.get("end-ip") else None
            elif kind == "fqdn":
                value = r.get("fqdn")
            elif kind == "geography":
                value = r.get("country")
            else:
                value = r.get("subnet") or r.get("fqdn")
            out.append(ParsedAddress(
                name=r.get("name") or "", kind=kind, value=value,
                comment=r.get("comment"),
                raw_definition=str(r),
            ))
        return out

    def address_groups(self, vdom: Optional[str] = None) -> List[ParsedAddress]:
        data = self._get("/api/v2/cmdb/firewall/addrgrp", vdom=self._firewall_vdom(vdom))
        out: List[ParsedAddress] = []
        for r in (data.get("results") or []):
            out.append(ParsedAddress(
                name=r.get("name") or "", kind="group",
                members=self._names(r.get("member")),
                comment=r.get("comment"),
                raw_definition=str(r),
            ))
        return out

    def services(self, vdom: Optional[str] = None) -> List[ParsedService]:
        # FortiOS REST API uses dot notation for nested config objects:
        # `firewall service custom` → /cmdb/firewall.service/custom (NOT
        # /cmdb/firewall/service/custom, which 400s).
        data = self._get("/api/v2/cmdb/firewall.service/custom", vdom=self._firewall_vdom(vdom))
        out: List[ParsedService] = []
        for r in (data.get("results") or []):
            tcp = r.get("tcp-portrange")
            udp = r.get("udp-portrange")
            icmp = r.get("icmptype")
            if tcp and udp:
                proto, ports = "tcp_udp", f"tcp:{tcp} udp:{udp}"
            elif tcp:
                proto, ports = "tcp", str(tcp)
            elif udp:
                proto, ports = "udp", str(udp)
            elif icmp:
                proto, ports = "icmp", f"type:{icmp}"
            else:
                proto = (r.get("protocol") or "tcp").lower()
                # protocol-number is a JSON int from the API (e.g. 51 = ESP).
                # Coerce to str so it fits the String `ports` column.
                pn = r.get("protocol-number")
                ports = str(pn) if pn is not None else None
            out.append(ParsedService(
                name=r.get("name") or "", protocol=proto, ports=ports,
                category=r.get("category"),
                comment=r.get("comment"),
                raw_definition=str(r),
            ))
        return out

    def service_groups(self, vdom: Optional[str] = None) -> List[ParsedService]:
        # See `services()` — same dot-notation rule applies to service groups.
        data = self._get("/api/v2/cmdb/firewall.service/group", vdom=self._firewall_vdom(vdom))
        out: List[ParsedService] = []
        for r in (data.get("results") or []):
            out.append(ParsedService(
                name=r.get("name") or "", protocol="group",
                members=self._names(r.get("member")),
                comment=r.get("comment"),
                raw_definition=str(r),
            ))
        return out

    def policies(self, vdom: Optional[str] = None) -> List[ParsedPolicy]:
        data = self._get("/api/v2/cmdb/firewall/policy", vdom=self._firewall_vdom(vdom))
        out: List[ParsedPolicy] = []
        for idx, r in enumerate((data.get("results") or []), start=1):
            out.append(ParsedPolicy(
                rule_id=str(r.get("policyid") or ""),
                name=r.get("name") or None,
                position=idx,
                enabled=(str(r.get("status") or "enable").lower() == "enable"),
                action=(r.get("action") or "accept").lower(),
                src_zones=self._names(r.get("srcintf")),
                dst_zones=self._names(r.get("dstintf")),
                src_addresses=self._names(r.get("srcaddr")),
                dst_addresses=self._names(r.get("dstaddr")),
                services=self._names(r.get("service")),
                applications=self._names(r.get("application-list"))
                              + self._names(r.get("application")),
                users=self._names(r.get("users")) + self._names(r.get("groups")),
                nat_enabled=(str(r.get("nat") or "disable").lower() == "enable"),
                log_traffic=r.get("logtraffic"),
                schedule=r.get("schedule"),
                comment=r.get("comments"),
                raw_definition=str(r),
            ))
        return out

    def fetch_policy_bundle(
        self, vdom: Optional[str] = None,
    ) -> ParsedFirewallConfig:
        """Pull all five policy-related collections in one call."""
        cfg = ParsedFirewallConfig()
        cfg.addresses = self.addresses(vdom)
        cfg.address_groups = self.address_groups(vdom)
        cfg.services = self.services(vdom)
        cfg.service_groups = self.service_groups(vdom)
        cfg.policies = self.policies(vdom)
        return cfg

    # ── VDOM enumeration ────────────────────────────────────────────

    def list_vdoms(self) -> List[str]:
        """Return list of configured VDOM names (empty if VDOMs are disabled)."""
        try:
            data = self._get("/api/v2/cmdb/system/vdom")
            return [v.get("name") for v in (data.get("results") or []) if v.get("name")]
        except FortinetAPIError:
            return []
