"""Path-aware firewall-flow resolver.

Traces the hop-by-hop chain of firewalls a ``src_ip → dst_ip`` flow
crosses by walking the latest routing-table snapshots, so the Policy
Lookup feature can evaluate policy **only at the hops the flow actually
traverses** instead of fanning out every firewall with a rule base.

Algorithm
---------

1. Load each device's latest successful routing snapshot and latest
   zone/interface snapshot once, into in-memory fabrics keyed by
   ``device_id``.
2. Find the ingress firewall — the device whose connected (``C``) subnet
   contains ``src_ip``. If no such device exists we fall back to the
   firewall with the longest-prefix route to ``dst_ip``; that's the most
   likely first hop when src lives outside the managed fabric.
3. At each device, do a longest-prefix match on the destination. If the
   winning route is directly connected, that device is the egress and
   the walk terminates. Otherwise the route's ``next_hop`` IP points at
   an adjacent device; we find that device by searching every fabric
   for an interface-subnet containing the next-hop address.
4. Repeat until dst is connected (``reached_dst``), no route matches
   (``no_route_to_dst``), next-hop is outside managed fabric
   (``next_hop_unknown``), loop (``loop``), or TTL
   (``ttl_exceeded``).

NAT is not yet applied — hops carry ``src_ip``/``dst_ip`` fields so
future work can rewrite them per-hop without changing the shape.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device
from ..models.routing import RoutingEntry, RoutingTableSnapshot
from ..models.zone import InterfaceEntry, ZoneSnapshot

logger = logging.getLogger(__name__)

MAX_HOPS = 10


# ── Public result types ────────────────────────────────────────────────

@dataclass
class Hop:
    """One firewall on the resolved path."""
    device_id: int
    device_display: str
    vdom: Optional[str] = None
    ingress_iface: Optional[str] = None
    ingress_zone: Optional[str] = None
    egress_iface: Optional[str] = None
    egress_zone: Optional[str] = None
    next_hop: Optional[str] = None       # IP the packet leaves toward
    route_type: Optional[str] = None     # C | S | B | O | …
    route_network: Optional[str] = None  # e.g. "10.5.30.0/24"
    src_ip: str = ""                     # seen at this hop (pre-NAT)
    dst_ip: str = ""


@dataclass
class Path:
    hops: List[Hop] = field(default_factory=list)
    complete: bool = False
    stop_reason: str = ""  # reached_dst | no_route_to_dst |
                           # next_hop_unknown | loop | ttl_exceeded |
                           # no_src_owner | no_routes


# ── Internal fabrics ───────────────────────────────────────────────────

# Each route tuple: (network_cidr, prefix_len, route_type, iface, next_hop, vdom)
_Route = Tuple[str, int, str, Optional[str], Optional[str], Optional[str]]
# Each interface tuple: (subnet_cidr, iface_name, zone_name, vdom)
_Iface = Tuple[str, Optional[str], Optional[str], Optional[str]]


@dataclass
class _DeviceFabric:
    routes: List[_Route] = field(default_factory=list)
    interfaces: List[_Iface] = field(default_factory=list)


async def _load_fabrics(
    db: AsyncSession,
) -> Tuple[Dict[int, _DeviceFabric], Dict[int, Device]]:
    """Preload topology data for every device with a usable snapshot.

    Snapshots are stored per (device_id, vdom) because Fortinet
    multi-VDOM firewalls have a separate routing table and zone/
    interface map for each VDOM. Loading only the latest snapshot
    per device would miss the VDOM that actually owns the flow of
    interest — e.g. on a firewall with ``root`` + ``Campus`` + ``WAN``
    VDOMs, the ``root`` VDOM is often nearly empty while the real user
    subnets live in ``Campus``.

    We therefore take the latest successful snapshot per
    (device_id, vdom) and merge the resulting routes/interfaces into
    the same per-device fabric. VDOM-level isolation matters for
    policy evaluation but not for topology discovery: if *any* VDOM
    on the device owns the flow, that firewall is on the path.
    """
    route_snaps = (await db.execute(
        select(RoutingTableSnapshot)
        .where(RoutingTableSnapshot.success.is_(True))
        .order_by(desc(RoutingTableSnapshot.fetched_at))
    )).scalars().all()
    latest_route_snaps: Dict[Tuple[int, Optional[str]], int] = {}
    for s in route_snaps:
        latest_route_snaps.setdefault((s.device_id, s.vdom), s.id)

    routes_per_device: Dict[int, List[_Route]] = {}
    if latest_route_snaps:
        snap_ids = list(latest_route_snaps.values())
        rows = (await db.execute(
            select(
                RoutingEntry.snapshot_id,
                RoutingEntry.network,
                RoutingEntry.prefix_length,
                RoutingEntry.route_type,
                RoutingEntry.interface,
                RoutingEntry.next_hop,
            ).where(RoutingEntry.snapshot_id.in_(snap_ids))
        )).all()
        snap_to_dev_vdom = {
            snap_id: (dev_id, vdom)
            for (dev_id, vdom), snap_id in latest_route_snaps.items()
        }
        for snap_id, net, pfx, rtype, iface, nh in rows:
            info = snap_to_dev_vdom.get(snap_id)
            if info is None:
                continue
            dev, vdom = info
            routes_per_device.setdefault(dev, []).append(
                (net or "", int(pfx or 0), rtype or "", iface, nh, vdom)
            )

    zone_snaps = (await db.execute(
        select(ZoneSnapshot)
        .where(ZoneSnapshot.success.is_(True))
        .order_by(desc(ZoneSnapshot.fetched_at))
    )).scalars().all()
    latest_zone_snaps: Dict[Tuple[int, Optional[str]], int] = {}
    for s in zone_snaps:
        latest_zone_snaps.setdefault((s.device_id, s.vdom), s.id)

    interfaces_per_device: Dict[int, List[_Iface]] = {}
    if latest_zone_snaps:
        snap_ids = list(latest_zone_snaps.values())
        rows = (await db.execute(
            select(
                InterfaceEntry.snapshot_id,
                InterfaceEntry.subnet_cidr,
                InterfaceEntry.interface_name,
                InterfaceEntry.zone_name,
            ).where(InterfaceEntry.snapshot_id.in_(snap_ids))
        )).all()
        snap_to_dev_vdom = {
            snap_id: (dev_id, vdom)
            for (dev_id, vdom), snap_id in latest_zone_snaps.items()
        }
        for snap_id, cidr, iname, zone in rows:
            info = snap_to_dev_vdom.get(snap_id)
            if info is None:
                continue
            dev, vdom = info
            interfaces_per_device.setdefault(dev, []).append(
                (cidr or "", iname, zone, vdom)
            )

    dev_ids = set(routes_per_device) | set(interfaces_per_device)
    fabrics = {
        did: _DeviceFabric(
            routes=routes_per_device.get(did, []),
            interfaces=interfaces_per_device.get(did, []),
        )
        for did in dev_ids
    }
    devices: Dict[int, Device] = {}
    if dev_ids:
        rows = (await db.execute(
            select(Device).where(Device.id.in_(list(dev_ids)))
        )).scalars().all()
        devices = {d.id: d for d in rows}
    return fabrics, devices


# ── Matching helpers ───────────────────────────────────────────────────

def _lpm_route(
    fab: _DeviceFabric, ip: str,
) -> Optional[Tuple[int, str, Optional[str], str, Optional[str], Optional[str]]]:
    """Longest-prefix match against the device's routing table.

    Returns ``(prefix_len, route_type, egress_iface, route_network,
    next_hop, vdom)`` of the winner, or ``None``. The default route
    (prefix length 0) is considered last — only when no more-specific
    route matches. See :func:`_lpm_routes_at_best` when the caller
    needs to disambiguate between equally-specific ECMP siblings.
    """
    best_all = _lpm_routes_at_best(fab, ip)
    return best_all[0] if best_all else None


def _lpm_routes_at_best(
    fab: _DeviceFabric, ip: str,
) -> List[Tuple[int, str, Optional[str], str, Optional[str], Optional[str]]]:
    """All routes that tie for the longest prefix covering ``ip``.

    Firewalls commonly carry multiple equally-specific routes for the
    same prefix — ECMP over two ISPs, a primary + failover tunnel, or
    just multiple static pointers installed for different paths. LPM
    alone can't pick the right one; the walker must try them and
    prefer whichever has a next-hop that lands on another managed
    device.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        return []
    best_plen = -1
    winners: List[
        Tuple[int, str, Optional[str], str, Optional[str], Optional[str]]
    ] = []
    for net_cidr, plen, rtype, iface, nh, vdom in fab.routes:
        try:
            net = ip_network(net_cidr, strict=False)
        except ValueError:
            continue
        if addr not in net:
            continue
        if plen > best_plen:
            best_plen = plen
            winners = [(plen, rtype or "", iface, net_cidr, nh, vdom)]
        elif plen == best_plen:
            winners.append((plen, rtype or "", iface, net_cidr, nh, vdom))
    return winners


def _lpm_subnet(
    fab: _DeviceFabric, ip: str,
) -> Optional[Tuple[int, Optional[str], Optional[str], Optional[str]]]:
    """Longest match against connected interface subnets.

    Returns ``(prefix_len, iface_name, zone_name, vdom)``. Only
    directly attached subnets count — this answers "does this device
    own the L2 broadcast domain that ``ip`` lives in?".

    Interfaces with prefix length 0 (``0.0.0.0/0``) are ignored: the
    Fortinet parser emits them for unconfigured physical ports, HA
    interfaces, and tunnel stubs, so treating them as owners would
    claim every device owns every IP and break the walk.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    best = None
    for cidr, iname, zone, vdom in fab.interfaces:
        if not cidr:
            continue
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0:
            continue
        if addr in net:
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, iname, zone, vdom)
    return best


def _find_owner_device(
    ip: str, fabrics: Dict[int, _DeviceFabric],
) -> Optional[Tuple[int, Optional[str], Optional[str], int, Optional[str]]]:
    """Device whose connected subnet contains ``ip``, if any.

    Returns ``(device_id, iface, zone, prefix_len, vdom)``. When
    several devices share the subnet (HA pair, transit link seen from
    both ends, etc.), the device with the most-specific prefix wins;
    ties break by lowest ``device_id`` for determinism.
    """
    best = None
    for did, fab in sorted(fabrics.items()):
        hit = _lpm_subnet(fab, ip)
        if hit is None:
            continue
        plen, iname, zone, vdom = hit
        if best is None or plen > best[3]:
            best = (did, iname, zone, plen, vdom)
    return best


def _find_next_hop_device(
    next_hop: str,
    fabrics: Dict[int, _DeviceFabric],
    exclude_dev_id: int,
    dst_ip: Optional[str] = None,
) -> Optional[Tuple[int, Optional[str], Optional[str], int, Optional[str]]]:
    """Pick the device that receives packets sent to ``next_hop``.

    Returns ``(device_id, iface, zone, prefix_len, vdom)``. Unlike
    :func:`_find_owner_device`, this deliberately skips
    ``exclude_dev_id`` — when a transit /28 or /30 is shared between
    three or more firewalls, the current device also sits on that
    subnet, but the packet's next hop is obviously one of the *other*
    sharers. Among the remaining candidates, prefer:

    1. a device that owns the ``dst_ip`` subnet directly (that's the
       egress firewall, which is what we're trying to reach); then
    2. a device with the longest route to ``dst_ip`` (more specific
       means closer to dst in the topology); then
    3. longer interface prefix on the transit subnet; then
    4. lowest device id for determinism.
    """
    candidates: List[
        Tuple[int, Optional[str], Optional[str], int, Optional[str]]
    ] = []
    for did, fab in sorted(fabrics.items()):
        if did == exclude_dev_id:
            continue
        hit = _lpm_subnet(fab, next_hop)
        if hit is None:
            continue
        plen, iname, zone, vdom = hit
        candidates.append((did, iname, zone, plen, vdom))
    if not candidates:
        return None

    def score(
        c: Tuple[int, Optional[str], Optional[str], int, Optional[str]]
    ) -> Tuple:
        did, _iname, _zone, plen, _vdom = c
        fab = fabrics[did]
        owns_dst = 0
        dst_route_plen = 0
        if dst_ip:
            owner_hit = _lpm_subnet(fab, dst_ip)
            owns_dst = 1 if owner_hit is not None else 0
            r = _lpm_route(fab, dst_ip)
            dst_route_plen = r[0] if r is not None else 0
        return (owns_dst, dst_route_plen, plen, -did)

    candidates.sort(key=score, reverse=True)
    return candidates[0]


def _rank_ingress_via_route(
    ip: str, fabrics: Dict[int, _DeviceFabric],
) -> List[Tuple[int, Optional[str], Optional[str]]]:
    """All candidate ingress firewalls for ``ip``, best-first.

    Returns a list of ``(device_id, ingress_iface, vdom)``. Under
    symmetric routing, any device holding a non-default route to
    ``ip`` could plausibly be the ingress. Ranking here is only a
    starting order — ``resolve_path`` then walks each candidate and
    picks the one whose walk actually completes to ``dst``, which is
    the real selection signal. The heuristic here just biases toward
    routes that are more likely to reflect true topology: more specific
    prefixes first, connected ahead of anything else, then lower device
    ids for determinism.
    """
    ranked: List[
        Tuple[Tuple[int, int, int], int, Optional[str], Optional[str]]
    ] = []
    for did, fab in sorted(fabrics.items()):
        route = _lpm_route(fab, ip)
        if route is None:
            continue
        plen, rtype, iface, _net, _nh, vdom = route
        if plen == 0:
            continue
        connected_bonus = 1 if rtype == "C" else 0
        ranked.append(((plen, connected_bonus, -did), did, iface, vdom))
    ranked.sort(reverse=True)
    return [(did, iface, vdom) for _key, did, iface, vdom in ranked]


def _zone_for_iface(fab: _DeviceFabric, iface_name: Optional[str]) -> Optional[str]:
    """Zone attached to ``iface_name`` on this device, if known."""
    if not iface_name:
        return None
    for _cidr, iname, zone, _vdom in fab.interfaces:
        if iname == iface_name:
            return zone
    return None


def _vdom_for_iface(
    fab: _DeviceFabric, iface_name: Optional[str],
) -> Optional[str]:
    """VDOM that owns ``iface_name`` on this device.

    Matches how Fortinet ingests interfaces: each VDOM has its own
    interface map, and we merged them into one fabric per device, so
    looking up by name gives us back the VDOM the interface was
    configured under.
    """
    if not iface_name:
        return None
    for _cidr, iname, _zone, vdom in fab.interfaces:
        if iname == iface_name:
            return vdom
    return None


def _closest_device_to(
    ip: str, fabrics: Dict[int, _DeviceFabric],
) -> Optional[int]:
    """Best device to use as the first hop when no device owns ``ip``.

    Ranks by the most specific route. Connected (``C``) routes beat
    non-connected at the same prefix length — a firewall that's on the
    L2 broadcast domain is always a better ingress than one that merely
    has a static pointer toward the subnet. Ties break by lowest id.
    """
    best = None  # (plen, is_connected, -did)
    best_did: Optional[int] = None
    for did, fab in sorted(fabrics.items()):
        route = _lpm_route(fab, ip)
        if route is None:
            continue
        plen, rtype, _iface, _net, _nh, _vdom = route
        key = (plen, 1 if rtype == "C" else 0, -did)
        if best is None or key > best:
            best = key
            best_did = did
    return best_did


# ── Public API ─────────────────────────────────────────────────────────

def _walk_from(
    start_dev_id: int,
    start_ingress_iface: Optional[str],
    start_ingress_zone: Optional[str],
    start_ingress_vdom: Optional[str],
    src_ip: str,
    dst_ip: str,
    fabrics: Dict[int, _DeviceFabric],
    devices: Dict[int, Device],
) -> Path:
    """Walk forward from a chosen ingress device to ``dst``.

    The hop's effective VDOM is taken from the egress interface: the
    VDOM that carries the packet out of this firewall is the one whose
    policy applies. For single-VDOM boxes this is None; for Fortinet
    multi-VDOMs, hop 1 on device 192.168.47.1 gets ``vdom='Campus'``
    when it exits via ``OverMPLS`` in the Campus VDOM.
    """
    path = Path()
    visited: set = set()
    current_dev_id = start_dev_id
    ingress_iface = start_ingress_iface
    ingress_zone = start_ingress_zone
    ingress_vdom = start_ingress_vdom

    for _ in range(MAX_HOPS):
        if current_dev_id in visited:
            path.stop_reason = "loop"
            return path
        visited.add(current_dev_id)

        fab = fabrics.get(current_dev_id)
        dev = devices.get(current_dev_id)
        if fab is None or dev is None:
            path.stop_reason = "device_missing"
            return path

        device_display = str(dev.ip_address)

        dst_owner = _lpm_subnet(fab, dst_ip)
        if dst_owner is not None:
            _plen, egress_iface, egress_zone, egress_vdom = dst_owner
            # For the egress (final) hop, prefer the VDOM that owns the
            # dst subnet — that's where the admission policy actually
            # lives — falling back to the ingress VDOM for single-VDOM
            # devices that carry no explicit VDOM label.
            hop_vdom = egress_vdom or ingress_vdom
            path.hops.append(Hop(
                device_id=dev.id,
                device_display=device_display,
                vdom=hop_vdom,
                ingress_iface=ingress_iface,
                ingress_zone=ingress_zone,
                egress_iface=egress_iface,
                egress_zone=egress_zone,
                route_type="C",
                src_ip=src_ip,
                dst_ip=dst_ip,
            ))
            path.complete = True
            path.stop_reason = "reached_dst"
            return path

        routes = _lpm_routes_at_best(fab, dst_ip)
        if not routes:
            path.hops.append(Hop(
                device_id=dev.id,
                device_display=device_display,
                vdom=ingress_vdom,
                ingress_iface=ingress_iface,
                ingress_zone=ingress_zone,
                src_ip=src_ip,
                dst_ip=dst_ip,
            ))
            path.stop_reason = "no_route_to_dst"
            return path

        # Of the equally-specific routes, pick one whose next-hop lands
        # on another managed device. Without this, an LPM siblings set
        # like [via 66.9.x.x (unmanaged), via 172.16.201.253 (= device
        # 4's port3)] can deterministically pick the dead-end by the
        # order the parser happened to emit rows.
        chosen = None
        chosen_adj = None
        for cand in routes:
            _plen, _rtype, _iface, _net, nh, _vdom = cand
            if not nh or nh == "0.0.0.0":
                chosen = cand
                chosen_adj = None
                break
            adj = _find_next_hop_device(
                nh, fabrics, exclude_dev_id=current_dev_id, dst_ip=dst_ip,
            )
            if adj is not None:
                chosen = cand
                chosen_adj = adj
                break
        if chosen is None:
            chosen = routes[0]

        _plen, rtype, egress_iface, net_cidr, next_hop, route_vdom = chosen
        egress_zone = _zone_for_iface(fab, egress_iface)
        # Prefer the **ingress** VDOM when it's known: on a multi-VDOM
        # Fortinet, the ingress-side policy is evaluated by the VDOM
        # that owns the ingress interface (e.g. Campus for VLAN257),
        # even if the packet later crosses an inter-VDOM link into
        # WAN. Routing may pick a WAN-VDOM /24 over a Campus-VDOM /0
        # because it's more specific, but that's about forwarding, not
        # policy: the first policy check happens in the ingress VDOM.
        hop_vdom = (
            ingress_vdom
            or _vdom_for_iface(fab, egress_iface)
            or route_vdom
        )

        path.hops.append(Hop(
            device_id=dev.id,
            device_display=device_display,
            vdom=hop_vdom,
            ingress_iface=ingress_iface,
            ingress_zone=ingress_zone,
            egress_iface=egress_iface,
            egress_zone=egress_zone,
            next_hop=next_hop,
            route_type=rtype,
            route_network=net_cidr,
            src_ip=src_ip,
            dst_ip=dst_ip,
        ))

        if not next_hop or next_hop == "0.0.0.0":
            path.stop_reason = "no_next_hop"
            return path

        if chosen_adj is None:
            chosen_adj = _find_next_hop_device(
                next_hop, fabrics, exclude_dev_id=current_dev_id, dst_ip=dst_ip,
            )
        if chosen_adj is None:
            path.stop_reason = "next_hop_unknown"
            return path
        adj_dev_id, adj_iface, adj_zone, _plen, adj_vdom = chosen_adj

        current_dev_id = adj_dev_id
        ingress_iface = adj_iface
        ingress_zone = adj_zone
        ingress_vdom = adj_vdom

    path.stop_reason = "ttl_exceeded"
    return path


async def resolve_path(
    db: AsyncSession,
    src_ip: str,
    dst_ip: str,
) -> Path:
    """Trace the firewall path a ``src_ip → dst_ip`` flow would take.

    Ingress selection can be ambiguous: several firewalls may hold a
    route to an external src (one with a real adjacency into the DC
    fabric, one pointing at an unmanaged upstream, etc.). We therefore
    enumerate candidate ingress devices, walk from each, and pick the
    candidate whose walk actually reaches ``dst``. If no candidate
    completes, the attempt with the longest hop chain wins as the best
    available approximation.
    """
    if not src_ip or not dst_ip:
        return Path(stop_reason="missing_endpoints")

    fabrics, devices = await _load_fabrics(db)
    if not fabrics:
        return Path(stop_reason="no_routes")

    # Build candidate ingress list in priority order.
    # Each candidate: (device_id, ingress_iface, ingress_zone, ingress_vdom).
    candidates: List[
        Tuple[int, Optional[str], Optional[str], Optional[str]]
    ] = []
    seen_dev: set = set()

    owner = _find_owner_device(src_ip, fabrics)
    if owner is not None and owner[0] not in seen_dev:
        candidates.append((owner[0], owner[1], owner[2], owner[4]))
        seen_dev.add(owner[0])

    for did, iface, vdom in _rank_ingress_via_route(src_ip, fabrics):
        if did in seen_dev:
            continue
        zone = _zone_for_iface(fabrics[did], iface)
        candidates.append((did, iface, zone, vdom))
        seen_dev.add(did)

    dst_owner = _find_owner_device(dst_ip, fabrics)
    if dst_owner is not None and dst_owner[0] not in seen_dev:
        candidates.append((dst_owner[0], None, None, None))
        seen_dev.add(dst_owner[0])

    cid = _closest_device_to(dst_ip, fabrics)
    if cid is not None and cid not in seen_dev:
        candidates.append((cid, None, None, None))
        seen_dev.add(cid)

    if not candidates:
        return Path(stop_reason="no_src_owner")

    best: Optional[Path] = None
    for dev_id, ing_iface, ing_zone, ing_vdom in candidates:
        attempt = _walk_from(
            dev_id, ing_iface, ing_zone, ing_vdom,
            src_ip, dst_ip, fabrics, devices,
        )
        if attempt.complete:
            return attempt
        if best is None or len(attempt.hops) > len(best.hops):
            best = attempt

    return best if best is not None else Path(stop_reason="no_src_owner")
