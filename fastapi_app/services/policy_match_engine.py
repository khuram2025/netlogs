"""
Policy Match Engine.

Answers the question *"would this flow match an existing firewall rule?"*
using the configured rule base (FirewallPolicy / FirewallAddressObject /
FirewallServiceObject) rather than traffic logs.

Complements the log-based lookup in ``db.clickhouse.ClickHouseClient
.policy_lookup``: the log lookup knows what *has* been seen, the config
engine knows what *would* match. The view layer merges the two so a
policy appears as config-only, log-only, or both.

Scope (P0 #2): first-match-wins per device+VDOM, Fortinet semantics
(any/all tokens, ipmask, iprange, fqdn, group, literal fallback). Zone
match is optional — if the caller does not supply a zone, zone constraints
are skipped. NAT and schedule are deliberately not yet considered.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import (
    IPv4Address,
    IPv4Network,
    ip_address,
    ip_network,
    summarize_address_range,
)
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device
from ..models.firewall_policy import (
    FirewallAddressObject,
    FirewallPolicy,
    FirewallPolicySnapshot,
    FirewallServiceObject,
)
from ..models.routing import RoutingEntry, RoutingTableSnapshot
from ..models.zone import InterfaceEntry, ZoneSnapshot

logger = logging.getLogger(__name__)


# ── Query / Result types ────────────────────────────────────────────────

@dataclass
class MatchQuery:
    """Flow description passed to the match engine."""
    dst_ip: str
    dst_port: int
    proto: str = "any"              # tcp | udp | icmp | any
    src_ip: Optional[str] = None
    src_zone: Optional[str] = None  # optional hint; skipped when absent
    dst_zone: Optional[str] = None
    dst_fqdn: Optional[str] = None  # original FQDN if the caller entered one
    app: Optional[str] = None       # optional PAN-OS App-ID (e.g. "ms-rdp")


@dataclass
class MatchResult:
    """Outcome of running ``MatchQuery`` against one device+VDOM."""
    device_id: int
    device_display: str
    vdom: Optional[str]
    matched: bool                    # False means implicit-deny
    action: str = "implicit-deny"
    policy_id: Optional[int] = None
    rule_id: Optional[str] = None
    policy_name: Optional[str] = None
    position: Optional[int] = None
    hit_count: Optional[int] = None
    last_hit_at: Optional[datetime] = None
    snapshot_fetched_at: Optional[datetime] = None
    reason: str = ""


# ── Resolvers ───────────────────────────────────────────────────────────

@dataclass
class ResolvedAddress:
    networks: List[IPv4Network] = field(default_factory=list)
    fqdns: List[str] = field(default_factory=list)
    any: bool = False


@dataclass
class ResolvedService:
    # A list of (proto, [(lo_port, hi_port), ...]) entries.
    entries: List[Tuple[str, List[Tuple[int, int]]]] = field(default_factory=list)
    any: bool = False


_ANY_TOKENS = {"all", "any", ""}
_LITERAL_SVC_RE = re.compile(r"^\s*(tcp|udp|icmp)[/:](\d+)(?:-(\d+))?\s*$", re.I)


def _parse_ipmask(value: Optional[str]) -> Optional[IPv4Network]:
    """Fortinet stores ipmask addresses as ``"10.5.30.10 255.255.255.255"``."""
    if not value:
        return None
    parts = value.split()
    try:
        if len(parts) == 2:
            return ip_network(f"{parts[0]}/{parts[1]}", strict=False)
        # Some imports normalise to CIDR already.
        return ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _parse_iprange(value: Optional[str]) -> List[IPv4Network]:
    """Expand ``"10.0.0.10-10.0.0.20"`` into the minimum set of CIDRs."""
    if not value or "-" not in value:
        return []
    try:
        lo, hi = [x.strip() for x in value.split("-", 1)]
        return list(summarize_address_range(ip_address(lo), ip_address(hi)))
    except (ValueError, TypeError):
        return []


def _parse_literal_network(name: str) -> Optional[IPv4Network]:
    """Fall back for addresses referenced by raw value (e.g. ``10.10.124.0``)."""
    try:
        return ip_network(name.strip(), strict=False)
    except ValueError:
        return None


def resolve_address(
    name: str,
    addr_dicts: Dict[str, Dict],
) -> ResolvedAddress:
    """Resolve a single address name (recursively expanding groups)."""
    out = ResolvedAddress()
    seen: set = set()
    stack = [name]
    while stack:
        cur = stack.pop()
        if cur is None:
            continue
        key = cur.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        if key.lower() in _ANY_TOKENS:
            out.any = True
            continue
        obj = addr_dicts.get(key)
        if obj is None:
            # Unknown name — try parsing as literal CIDR/IP.
            net = _parse_literal_network(key)
            if net is not None:
                out.networks.append(net)
            continue
        kind = (obj.get("kind") or "").lower()
        if kind == "ipmask":
            net = _parse_ipmask(obj.get("value"))
            if net is not None:
                out.networks.append(net)
        elif kind == "iprange":
            out.networks.extend(_parse_iprange(obj.get("value")))
        elif kind == "fqdn":
            v = (obj.get("value") or "").strip().lower()
            if v:
                out.fqdns.append(v)
        elif kind == "group":
            for member in (obj.get("members") or []):
                stack.append(member)
        # geography / dynamic: deliberately ignored in MVP.
    return out


def _parse_port_spec(spec: Optional[str]) -> List[Tuple[int, int]]:
    """Parse ``"80"`` / ``"1-65535"`` / ``"80,443,1000-2000"``."""
    ranges: List[Tuple[int, int]] = []
    for token in re.split(r"[\s,]+", (spec or "").strip()):
        if not token:
            continue
        if "-" in token:
            try:
                lo_s, hi_s = token.split("-", 1)
                ranges.append((int(lo_s), int(hi_s)))
            except ValueError:
                continue
        else:
            try:
                n = int(token)
                ranges.append((n, n))
            except ValueError:
                continue
    return ranges


def _expand_service_object(
    svc_obj: Dict,
) -> Tuple[List[Tuple[str, List[Tuple[int, int]]]], bool]:
    """Normalise one service object row to (entries, is_any)."""
    proto = (svc_obj.get("protocol") or "").lower()
    ports = svc_obj.get("ports")
    if proto == "ip":
        # Fortinet ALL has ports='0'; any other proto number means a raw IP
        # protocol that we don't match on port. Treat both as "any".
        return [], True
    if proto == "tcp" or proto == "udp":
        return [(proto, _parse_port_spec(ports))], False
    if proto == "icmp" or proto == "icmp6":
        return [(proto, [])], False
    if proto == "tcp_udp":
        out: List[Tuple[str, List[Tuple[int, int]]]] = []
        for chunk in (ports or "").split():
            if ":" in chunk:
                p, spec = chunk.split(":", 1)
                out.append((p.lower(), _parse_port_spec(spec)))
        return out, False
    return [], False


def resolve_service(
    name: str,
    svc_dicts: Dict[str, Dict],
) -> ResolvedService:
    """Resolve a single service name (recursive group expansion)."""
    out = ResolvedService()
    seen: set = set()
    stack = [name]
    while stack:
        cur = stack.pop()
        if cur is None:
            continue
        key = cur.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        if key.lower() in _ANY_TOKENS:
            out.any = True
            continue
        obj = svc_dicts.get(key)
        if obj is None:
            # Try ``tcp/3390`` / ``udp/500-600`` literal.
            m = _LITERAL_SVC_RE.match(key)
            if m:
                p = m.group(1).lower()
                lo = int(m.group(2))
                hi = int(m.group(3) or m.group(2))
                if p == "icmp":
                    out.entries.append((p, []))
                else:
                    out.entries.append((p, [(lo, hi)]))
            continue
        if (obj.get("protocol") or "").lower() == "group":
            for member in (obj.get("members") or []):
                stack.append(member)
            continue
        entries, is_any = _expand_service_object(obj)
        if is_any:
            out.any = True
        out.entries.extend(entries)
    return out


# ── Match predicates ────────────────────────────────────────────────────

def _address_matches(resolved: ResolvedAddress, ip: Optional[str],
                     fqdn: Optional[str]) -> bool:
    """True iff the resolved address set contains the query's ip/fqdn."""
    if resolved.any:
        return True
    # FQDN match: equal or sub-domain of an FQDN-kind object.
    if fqdn and resolved.fqdns:
        f = fqdn.lower()
        for candidate in resolved.fqdns:
            if f == candidate or f.endswith("." + candidate):
                return True
    if not ip:
        # Caller omitted the value — do not constrain on this axis.
        return True
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    for net in resolved.networks:
        if addr in net:
            return True
    return False


def _service_matches(resolved: ResolvedService, proto: str, port: int) -> bool:
    """True iff the resolved service covers (proto, port)."""
    if resolved.any:
        return True
    p = (proto or "any").lower()
    for svc_proto, ranges in resolved.entries:
        # ICMP services are port-less; match regardless of the numeric port.
        if svc_proto == "icmp":
            if p in ("icmp", "any"):
                return True
            continue
        if p == "any" or p == svc_proto:
            if any(lo <= port <= hi for lo, hi in ranges):
                return True
    return False


def _zone_matches(rule_zones: Optional[List[str]],
                  ref_zone: Optional[str]) -> bool:
    """Zone check — lenient when either side is unknown/any."""
    if not rule_zones:
        return True
    if any((z or "").lower() in _ANY_TOKENS for z in rule_zones):
        return True
    if not ref_zone:
        return True
    return ref_zone in rule_zones


def _application_matches(rule_apps: Optional[List[str]],
                         query_app: Optional[str]) -> bool:
    """Check whether a rule's App-ID constraint can match the query.

    PAN-OS rules frequently pin traffic to specific L7 applications (e.g.
    ``applications=['ms-rdp']``); the L4 service field can simultaneously
    be ``services=['any']``. Without an App-ID classifier we cannot decide
    whether an arbitrary (src, dst, proto, port) flow belongs to a given
    App-ID — so rules that constrain on specific apps must be skipped
    when the caller has no app context. Returning True from this check
    effectively means "no app constraint (or one the caller satisfies)".

    Without this guard, a rule like ``Block_Icmp_timestamp`` (services=any,
    applications=[icmp-timestamp], deny) swallows TCP:3389 queries at
    position 1 because the engine can only see ``services=any``.

    Rules with ``applications=[]`` or ``['any']``/``['all']`` don't
    constrain by app and always pass this check. Fortinet rules normally
    leave applications empty, so this predicate is a no-op for them.
    """
    if not rule_apps:
        return True
    if all((a or "").lower() in _ANY_TOKENS for a in rule_apps):
        return True
    if query_app:
        q = query_app.lower()
        return any((a or "").lower() == q for a in rule_apps)
    # Rule constrains by a specific app and the query doesn't tell us
    # which one — be conservative and skip.
    return False


# ── Per-device matcher ──────────────────────────────────────────────────

def match_device(
    device_id: int,
    device_display: str,
    vdom: Optional[str],
    policies: Iterable[FirewallPolicy],
    addr_objs: Iterable[FirewallAddressObject],
    svc_objs: Iterable[FirewallServiceObject],
    query: MatchQuery,
    snapshot_fetched_at: Optional[datetime] = None,
) -> MatchResult:
    """Return the first-match policy for ``query`` on this device+VDOM.

    When no policy matches, returns a synthetic ``implicit-deny`` result.
    """
    addr_dicts = {
        a.name: {"kind": a.kind, "value": a.value, "members": a.members}
        for a in addr_objs
    }
    svc_dicts = {
        s.name: {"protocol": s.protocol, "ports": s.ports, "members": s.members}
        for s in svc_objs
    }
    addr_cache: Dict[Tuple[str, ...], ResolvedAddress] = {}
    svc_cache: Dict[Tuple[str, ...], ResolvedService] = {}

    def _resolve_addr_list(names: Optional[List[str]]) -> ResolvedAddress:
        key = tuple(names or [])
        r = addr_cache.get(key)
        if r is not None:
            return r
        out = ResolvedAddress()
        for n in names or []:
            part = resolve_address(n, addr_dicts)
            out.networks.extend(part.networks)
            out.fqdns.extend(part.fqdns)
            out.any = out.any or part.any
        addr_cache[key] = out
        return out

    def _resolve_svc_list(names: Optional[List[str]]) -> ResolvedService:
        key = tuple(names or [])
        r = svc_cache.get(key)
        if r is not None:
            return r
        out = ResolvedService()
        for n in names or []:
            part = resolve_service(n, svc_dicts)
            out.entries.extend(part.entries)
            out.any = out.any or part.any
        svc_cache[key] = out
        return out

    for p in policies:
        if not p.enabled:
            continue
        if not _zone_matches(p.src_zones, query.src_zone):
            continue
        if not _zone_matches(p.dst_zones, query.dst_zone):
            continue
        if not _address_matches(
            _resolve_addr_list(p.src_addresses), query.src_ip, None
        ):
            continue
        if not _address_matches(
            _resolve_addr_list(p.dst_addresses), query.dst_ip, query.dst_fqdn
        ):
            continue
        if not _application_matches(p.applications, query.app):
            continue
        if not _service_matches(
            _resolve_svc_list(p.services), query.proto, query.dst_port
        ):
            continue
        return MatchResult(
            device_id=device_id,
            device_display=device_display,
            vdom=vdom,
            matched=True,
            action=p.action or "accept",
            policy_id=p.id,
            rule_id=p.rule_id,
            policy_name=(p.name or p.rule_id or f"policy-{p.position}"),
            position=p.position,
            hit_count=p.hit_count,
            last_hit_at=p.last_hit_at,
            snapshot_fetched_at=snapshot_fetched_at,
            reason="first-match in config",
        )

    return MatchResult(
        device_id=device_id,
        device_display=device_display,
        vdom=vdom,
        matched=False,
        action="implicit-deny",
        snapshot_fetched_at=snapshot_fetched_at,
        reason="no rule matched; vendor default applies",
    )


# ── Path selection ──────────────────────────────────────────────────────


@dataclass
class _DevicePathHint:
    """Per-device info injected into the match query after path selection."""
    src_zone: Optional[str] = None
    dst_zone: Optional[str] = None


def _longest_prefix_match(
    ip: str, routes: List[Tuple[str, int, str, Optional[str]]],
) -> Optional[Tuple[int, str, Optional[str]]]:
    """Find the most-specific route covering ``ip``.

    Each route tuple is ``(network_cidr, prefix_length, route_type, interface)``.
    Returns ``(prefix_length, route_type, interface)`` of the winner, or
    ``None`` if nothing matches.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    best: Optional[Tuple[int, str, Optional[str]]] = None
    for net_cidr, prefix_len, rtype, iface in routes:
        try:
            net = ip_network(net_cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            if best is None or prefix_len > best[0]:
                best = (prefix_len, rtype or "", iface)
    return best


def _longest_subnet_match(
    ip: str, interfaces: List[Tuple[str, Optional[str], Optional[str]]],
) -> Optional[Tuple[int, str, Optional[str]]]:
    """Find the most-specific interface subnet that contains ``ip``.

    Each interface tuple is ``(subnet_cidr, interface_name, zone_name)``.
    Returns ``(prefix_length, interface_name, zone_name)`` of the winner.
    Only interfaces with a non-empty ``subnet_cidr`` are considered.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    best: Optional[Tuple[int, str, Optional[str]]] = None
    for cidr, iface, zone in interfaces:
        if not cidr:
            continue
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, iface or "", zone)
    return best


async def _path_device_hints(
    db: AsyncSession, query: MatchQuery,
) -> Optional[Dict[int, _DevicePathHint]]:
    """Return ``{device_id: _DevicePathHint}`` for firewalls in the flow path.

    Selection heuristic, strongest first:
      1. Devices with a directly-connected (``C``) route whose network
         contains ``query.dst_ip`` — last-hop firewalls that own the
         destination subnet.
      2. Otherwise, devices with the longest non-default prefix route to
         ``query.dst_ip`` (static / dynamic). Ties at the max prefix all
         qualify (they may be in sequence).
      3. When ``query.src_ip`` is also provided, tighten further by
         keeping only devices that ALSO have a connected route / interface
         for the src subnet. The filter is dropped if it would empty the
         result (src may be reached via default route on every candidate).

    For each surviving device, we also compute a per-device hint pair
    ``(src_zone, dst_zone)`` derived from:
      - direct interface-subnet match (``InterfaceEntry.subnet_cidr`` →
        ``zone_name``), preferred because interfaces are authoritative
        about zone membership, AND
      - routing-table fallback (route → egress interface → zone) when
        the IP isn't on a directly-connected subnet (typical for src
        that lives behind another hop).

    Returns ``None`` when no routing data exists anywhere so the caller
    can fall back to evaluating every device with a policy snapshot.
    """
    # ---- Load latest successful routing snapshots and their entries ----
    route_snaps = (await db.execute(
        select(RoutingTableSnapshot)
        .where(RoutingTableSnapshot.success.is_(True))
        .order_by(desc(RoutingTableSnapshot.fetched_at))
    )).scalars().all()
    latest_route_snap: Dict[int, int] = {}
    for s in route_snaps:
        latest_route_snap.setdefault(s.device_id, s.id)
    if not latest_route_snap:
        return None

    route_snap_ids = list(latest_route_snap.values())
    route_rows = (await db.execute(
        select(
            RoutingEntry.snapshot_id,
            RoutingEntry.network,
            RoutingEntry.prefix_length,
            RoutingEntry.route_type,
            RoutingEntry.interface,
        ).where(RoutingEntry.snapshot_id.in_(route_snap_ids))
    )).all()

    route_snap_to_device = {v: k for k, v in latest_route_snap.items()}
    routes_per_device: Dict[int, List[Tuple[str, int, str, Optional[str]]]] = {}
    for snap_id, net, pfx, rtype, iface in route_rows:
        dev = route_snap_to_device.get(snap_id)
        if dev is None:
            continue
        routes_per_device.setdefault(dev, []).append(
            (net or "", int(pfx or 0), rtype or "", iface)
        )
    if not routes_per_device:
        return None

    # ---- Load latest zone snapshots and their interfaces ----
    # Zones and interfaces live under ZoneSnapshot — one snapshot per
    # device+vdom. We take the newest successful one per device.
    zone_snaps = (await db.execute(
        select(ZoneSnapshot)
        .where(ZoneSnapshot.success.is_(True))
        .order_by(desc(ZoneSnapshot.fetched_at))
    )).scalars().all()
    latest_zone_snap: Dict[int, int] = {}
    for s in zone_snaps:
        latest_zone_snap.setdefault(s.device_id, s.id)

    interfaces_per_device: Dict[
        int, List[Tuple[str, Optional[str], Optional[str]]]
    ] = {}
    iface_to_zone: Dict[Tuple[int, str], Optional[str]] = {}
    if latest_zone_snap:
        zone_snap_ids = list(latest_zone_snap.values())
        iface_rows = (await db.execute(
            select(
                InterfaceEntry.snapshot_id,
                InterfaceEntry.subnet_cidr,
                InterfaceEntry.interface_name,
                InterfaceEntry.zone_name,
            ).where(InterfaceEntry.snapshot_id.in_(zone_snap_ids))
        )).all()
        zone_snap_to_device = {v: k for k, v in latest_zone_snap.items()}
        for snap_id, cidr, name, zone in iface_rows:
            dev = zone_snap_to_device.get(snap_id)
            if dev is None:
                continue
            interfaces_per_device.setdefault(dev, []).append(
                (cidr or "", name, zone)
            )
            if name:
                iface_to_zone[(dev, name)] = zone

    def _zone_for_ip(dev_id: int, ip: Optional[str]) -> Optional[str]:
        """Interface-subnet match first (authoritative), else route-egress
        interface → zone. Returns None if neither path yields a zone."""
        if not ip:
            return None
        hit = _longest_subnet_match(ip, interfaces_per_device.get(dev_id, []))
        if hit is not None and hit[2]:
            return hit[2]
        route = _longest_prefix_match(ip, routes_per_device.get(dev_id, []))
        if route is not None and route[2]:
            return iface_to_zone.get((dev_id, route[2]))
        return None

    # ---- Tier 1 / Tier 2: rank candidates by dst reachability ----
    connected: set = set()
    ranked: Dict[int, Tuple[int, str, Optional[str]]] = {}
    for dev_id, routes in routes_per_device.items():
        best = _longest_prefix_match(query.dst_ip, routes)
        if best is None:
            continue
        ranked[dev_id] = best
        if best[1] == "C":
            connected.add(dev_id)

    candidates: set
    if connected:
        candidates = connected
    elif ranked:
        non_default = {d: r for d, r in ranked.items() if r[0] > 0}
        pool = non_default or ranked
        max_pfx = max(r[0] for r in pool.values())
        candidates = {d for d, r in pool.items() if r[0] == max_pfx}
    else:
        return None

    # ---- Tier 3: refine by src reachability (soft filter) ----
    if query.src_ip:
        src_reachable: set = set()
        for dev_id in candidates:
            # Direct subnet? strong signal.
            if _longest_subnet_match(query.src_ip, interfaces_per_device.get(dev_id, [])) is not None:
                src_reachable.add(dev_id)
                continue
            # Non-default route? moderate signal — the firewall has
            # explicit knowledge of the src subnet.
            route = _longest_prefix_match(query.src_ip, routes_per_device.get(dev_id, []))
            if route is not None and route[0] > 0:
                src_reachable.add(dev_id)
        if src_reachable:
            candidates = src_reachable

    # ---- Compute per-device zone hints ----
    hints: Dict[int, _DevicePathHint] = {}
    for dev_id in candidates:
        hints[dev_id] = _DevicePathHint(
            src_zone=_zone_for_ip(dev_id, query.src_ip),
            dst_zone=_zone_for_ip(dev_id, query.dst_ip),
        )
    return hints


# ── Orchestrator ────────────────────────────────────────────────────────

async def match_all_devices(
    db: AsyncSession,
    query: MatchQuery,
) -> List[MatchResult]:
    """Run ``match_device`` for every device with a policy snapshot.

    One result per ``(device_id, vdom)`` — because policy lookups are
    scoped to a single VDOM on Fortinet.
    """
    # Find the latest snapshot per (device_id, vdom) that succeeded.
    # ``DISTINCT ON`` isn't in the generic SQL layer so we pull candidates
    # and pick the newest in Python — the set is small (dozens of devices).
    snapshots = (await db.execute(
        select(FirewallPolicySnapshot)
        .where(FirewallPolicySnapshot.success.is_(True))
        .order_by(desc(FirewallPolicySnapshot.fetched_at))
    )).scalars().all()

    latest_by_key: Dict[Tuple[int, Optional[str]], FirewallPolicySnapshot] = {}
    for s in snapshots:
        k = (s.device_id, s.vdom)
        if k not in latest_by_key:
            latest_by_key[k] = s
    if not latest_by_key:
        return []

    # Path-first filter: if we have usable routing data, restrict the
    # evaluated set to firewalls the flow actually traverses and also
    # auto-resolve per-device src/dst zones so zone-scoped rules match
    # correctly. On a fresh install with no route/zone snapshots this
    # is a no-op — we keep the original every-device behaviour and the
    # lenient zone match.
    path_hints = await _path_device_hints(db, query)
    if path_hints is not None:
        latest_by_key = {
            k: v for k, v in latest_by_key.items() if k[0] in path_hints
        }
        if not latest_by_key:
            # No device with both a policy snapshot AND a matching route.
            # Return empty instead of fanning out every snapshotted box.
            return []

    device_ids = sorted({k[0] for k in latest_by_key.keys()})
    dev_rows = (await db.execute(
        select(Device).where(Device.id.in_(device_ids))
    )).scalars().all()
    dev_by_id = {d.id: d for d in dev_rows}

    results: List[MatchResult] = []
    for (device_id, vdom), snap in latest_by_key.items():
        dev = dev_by_id.get(device_id)
        if dev is None:
            continue
        device_display = f"{dev.ip_address}_{vdom}" if vdom else str(dev.ip_address)

        policies = (await db.execute(
            select(FirewallPolicy)
            .where(FirewallPolicy.snapshot_id == snap.id)
            .order_by(FirewallPolicy.position.asc())
        )).scalars().all()
        addr_objs = (await db.execute(
            select(FirewallAddressObject)
            .where(FirewallAddressObject.snapshot_id == snap.id)
        )).scalars().all()
        svc_objs = (await db.execute(
            select(FirewallServiceObject)
            .where(FirewallServiceObject.snapshot_id == snap.id)
        )).scalars().all()

        if not policies:
            continue

        # Per-device query: reuse the caller's fields but inject the
        # auto-resolved zone hints. Zones are per-firewall because each
        # device sees src/dst through its own interface-to-zone map.
        # When path_hints is None we keep the original zones (lenient
        # match path).
        device_query = query
        hint = path_hints.get(device_id) if path_hints else None
        if hint is not None:
            device_query = MatchQuery(
                dst_ip=query.dst_ip,
                dst_port=query.dst_port,
                proto=query.proto,
                src_ip=query.src_ip,
                src_zone=query.src_zone or hint.src_zone,
                dst_zone=query.dst_zone or hint.dst_zone,
                dst_fqdn=query.dst_fqdn,
                app=query.app,
            )

        results.append(match_device(
            device_id=device_id,
            device_display=device_display,
            vdom=vdom,
            policies=policies,
            addr_objs=addr_objs,
            svc_objs=svc_objs,
            query=device_query,
            snapshot_fetched_at=snap.fetched_at,
        ))
    return results
