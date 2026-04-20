"""
PolicyAnalyticsService — Phase 1 widgets (config-only, no log dependency).

Computes hygiene/risk insights from the FirewallPolicy / FirewallAddressObject
/ FirewallServiceObject snapshot already persisted by FirewallPolicyService.
All five widgets here are SQL-cheap and reproduce the operationally-useful
parts of Tufin's Policy Browser, FireMon's rule scorecard, and PAN's Policy
Optimizer that don't need traffic correlation.

A widget = a small dataclass the template renders directly. The service is
stateless and idempotent: pass policies/addresses/services from the device
detail handler, get back analytics — no DB writes.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Tokens that all vendors use to mean "match anything" ──────────────
# Normalised lowercase so the comparisons below stay simple.
_ANY_NAMES: FrozenSet[str] = frozenset({"all", "any", "any_addr", "any_address", "*"})
_ANY_SERVICE_NAMES: FrozenSet[str] = frozenset({"all", "any", "all_services"})
_ANY_ZONE_NAMES: FrozenSet[str] = frozenset({"any", "all"})


def _norm_set(items: Optional[List[str]]) -> FrozenSet[str]:
    """Normalise a list of names into a lowercase frozenset for set algebra."""
    return frozenset((s or "").strip().lower() for s in (items or []) if s)


def _is_any(items: Optional[List[str]], any_set: FrozenSet[str] = _ANY_NAMES) -> bool:
    """True if the list contains an 'any/all' token (or is empty, which some
    vendors render as implicit-any)."""
    n = _norm_set(items)
    return not n or any(t in n for t in any_set)


# ─────────────────────────────────────────────────────────────────────
# Result dataclasses (kept JSON-serialisable for easy template use)
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ShadowedRule:
    rule: Any                 # FirewallPolicy
    shadowed_by: Any          # FirewallPolicy that fully covers it
    reason: str               # human-readable explanation


@dataclass
class RedundantRule:
    rule: Any                 # the duplicate / strict-subset rule
    duplicate_of: Any         # the canonical rule it copies
    reason: str


@dataclass
class PermissivenessRow:
    rule: Any
    score: int                # 0 (tight) … 100 (any-any-any-no-log)
    flags: List[str]          # human chips: ["any-src", "any-svc", "log-off"]
    band: str                 # 'critical' | 'high' | 'medium' | 'low'


@dataclass
class ObjectHygiene:
    total_addrs: int
    referenced_addrs: int
    unreferenced_addrs: List[Any]
    duplicate_addr_groups: List[Tuple[str, List[Any]]]   # (value, [objects])
    total_services: int
    referenced_services: int
    unreferenced_services: List[Any]


@dataclass
class UnloggedPermitRow:
    rule: Any
    reason: str


@dataclass
class PolicyHits:
    """Per-policy hit count and last-seen timestamp for one time window."""
    policy_name: str
    hits: int = 0
    last_seen: Optional[str] = None


@dataclass
class TopTalker:
    srcip: str
    dstip: str
    dstport: int
    proto: int
    hits: int


@dataclass
class ImplicitDenyRow:
    """Top denied tuples without a matching policyname — i.e. flows hitting
    the implicit-deny default. Suggests a missing rule."""
    srcip: str
    dstip: str
    dstport: int
    proto: int
    hits: int


@dataclass
class ReachabilityCell:
    """One cell of the zone reachability matrix."""
    src_zone: str
    dst_zone: str
    rule_count: int = 0       # # of permit rules that authorise this pair
    deny_rule_count: int = 0
    observed_hits: int = 0
    state: str = "gap"        # gap | aligned | over-provisioned | unauthorised | denied


@dataclass
class ReachabilityMatrix:
    src_zones: List[str]      # row order
    dst_zones: List[str]      # column order
    cells: Dict[Tuple[str, str], ReachabilityCell]
    has_observed: bool        # True if log-resolved data is included

    def cell(self, src: str, dst: str) -> ReachabilityCell:
        return self.cells.get((src, dst), ReachabilityCell(src_zone=src, dst_zone=dst))


@dataclass
class PolicyAnalyticsBundle:
    """Everything the Analytics tab needs to render in one render pass."""
    # KPI tiles
    kpi_active_rules: int
    kpi_disabled_rules: int
    kpi_shadowed_count: int
    kpi_redundant_count: int
    kpi_unlogged_permits: int
    kpi_avg_permissiveness: int
    kpi_critical_permissiveness: int
    kpi_unreferenced_objects: int
    # Phase 2 KPIs (log-derived; defaults keep the dashboard renderable
    # before logs are joined).
    kpi_zero_hit_30d: int = 0
    kpi_total_hits_30d: int = 0

    # Widgets
    shadowed: List[ShadowedRule] = field(default_factory=list)
    redundant: List[RedundantRule] = field(default_factory=list)
    permissiveness: List[PermissivenessRow] = field(default_factory=list)
    unlogged_permits: List[UnloggedPermitRow] = field(default_factory=list)
    object_hygiene: Optional[ObjectHygiene] = None

    # Phase 2 widgets (log-join). Mapped by lowercase policy_name for fast
    # template lookup.
    hits_by_name: Dict[str, PolicyHits] = field(default_factory=dict)
    zero_hit_rules: List[Any] = field(default_factory=list)         # FirewallPolicy
    implicit_deny: List[ImplicitDenyRow] = field(default_factory=list)
    log_window_hours: int = 0                                       # 0 = unknown / not joined

    # Phase 3: per-policy daily hits over N days for sparklines + heatmap.
    # Same lowercase-name key as `hits_by_name`. Empty if log join skipped.
    daily_hits: Dict[str, List[int]] = field(default_factory=dict)
    daily_window_days: int = 0

    # Phase 4: zone-pair reachability matrix. Empty if no zone data.
    reachability: Optional[ReachabilityMatrix] = None


# ─────────────────────────────────────────────────────────────────────
# The service
# ─────────────────────────────────────────────────────────────────────

class PolicyAnalyticsService:

    # ── Shadowed / redundant rule detection ────────────────────────
    # We treat rule M as "covering" rule N when M sits earlier in
    # position AND every dimension of N is a (non-strict) subset of M's
    # match-set, AND the actions are compatible (M.action != N.action means
    # N is dead — that's a shadow). Same matching-set with same action =
    # redundant (N is duplicate work).
    #
    # "Covers" semantics per dimension: M covers N if M is `any` OR
    # _norm_set(N) is a subset of _norm_set(M). We don't try to recursively
    # expand address groups — that's a P3 enhancement once we have a
    # resolver. For now this catches the most common dead/duplicate rules.

    @classmethod
    def _covers(cls, m_items: Optional[List[str]], n_items: Optional[List[str]],
                any_set: FrozenSet[str] = _ANY_NAMES) -> bool:
        m_n = _norm_set(m_items)
        n_n = _norm_set(n_items)
        if not m_n or any(t in m_n for t in any_set):
            return True
        if not n_n:
            # N is implicit-any but M isn't — N is broader, M does not cover it
            return False
        return n_n.issubset(m_n)

    @classmethod
    def _covers_zone(cls, m, n) -> bool:
        return cls._covers(m, n, any_set=_ANY_ZONE_NAMES)

    @classmethod
    def _covers_svc(cls, m, n) -> bool:
        return cls._covers(m, n, any_set=_ANY_SERVICE_NAMES)

    @classmethod
    def find_shadowed_and_redundant(cls, policies: List[Any]
                                     ) -> Tuple[List[ShadowedRule], List[RedundantRule]]:
        shadowed: List[ShadowedRule] = []
        redundant: List[RedundantRule] = []
        # Compare every rule against earlier (lower position) enabled rules.
        # O(n²) on rule count — fine for hundreds of rules; if we ever cross
        # ~5k we'll need bucketing by zone-pair first.
        ordered = [p for p in sorted(policies, key=lambda r: r.position) if p.enabled]
        for i, n in enumerate(ordered):
            for m in ordered[:i]:
                if (cls._covers_zone(m.src_zones, n.src_zones)
                    and cls._covers_zone(m.dst_zones, n.dst_zones)
                    and cls._covers(m.src_addresses, n.src_addresses)
                    and cls._covers(m.dst_addresses, n.dst_addresses)
                    and cls._covers_svc(m.services, n.services)):
                    if (m.action or "").lower() == (n.action or "").lower():
                        redundant.append(RedundantRule(
                            rule=n, duplicate_of=m,
                            reason=f"Rule #{n.position} is fully covered by earlier rule "
                                   f"#{m.position} with the same action ({m.action})."
                        ))
                    else:
                        shadowed.append(ShadowedRule(
                            rule=n, shadowed_by=m,
                            reason=f"Rule #{n.position} ({n.action}) can never be reached — "
                                   f"earlier rule #{m.position} ({m.action}) already matches "
                                   f"every flow it would have."
                        ))
                    break  # first cover wins; no need to keep searching
        return shadowed, redundant

    # ── Permissiveness scoring ─────────────────────────────────────
    # Weighted: each "any" dimension adds points; log-off on a permit adds a
    # bonus risk. A pure any/any/any/log-off rule scores 100. Bands:
    #   ≥80 critical, ≥60 high, ≥40 medium, <40 low.

    _WEIGHTS = {
        "any-src-zone": 10, "any-dst-zone": 10,
        "any-src-addr": 25, "any-dst-addr": 25,
        "any-svc": 20,
        "log-off": 10,
    }

    @classmethod
    def score_permissiveness(cls, policies: List[Any]) -> List[PermissivenessRow]:
        rows: List[PermissivenessRow] = []
        for p in sorted(policies, key=lambda r: r.position):
            flags: List[str] = []
            score = 0
            if _is_any(p.src_zones, _ANY_ZONE_NAMES):
                flags.append("any-src-zone"); score += cls._WEIGHTS["any-src-zone"]
            if _is_any(p.dst_zones, _ANY_ZONE_NAMES):
                flags.append("any-dst-zone"); score += cls._WEIGHTS["any-dst-zone"]
            if _is_any(p.src_addresses):
                flags.append("any-src-addr"); score += cls._WEIGHTS["any-src-addr"]
            if _is_any(p.dst_addresses):
                flags.append("any-dst-addr"); score += cls._WEIGHTS["any-dst-addr"]
            if _is_any(p.services, _ANY_SERVICE_NAMES):
                flags.append("any-svc"); score += cls._WEIGHTS["any-svc"]
            # Logging penalty only meaningful for permit rules
            if (p.action or "").lower() in ("accept", "allow", "pass") and (p.log_traffic or "").lower() in ("disable", "", "none"):
                flags.append("log-off"); score += cls._WEIGHTS["log-off"]
            band = (
                "critical" if score >= 80 else
                "high"     if score >= 60 else
                "medium"   if score >= 40 else
                "low"
            )
            rows.append(PermissivenessRow(rule=p, score=score, flags=flags, band=band))
        # Sort highest-risk first — this is what an analyst wants to see.
        rows.sort(key=lambda r: -r.score)
        return rows

    # ── Unlogged permit rules ──────────────────────────────────────
    # Permit rules without traffic logging are the worst kind of blind spot:
    # whatever they let through is invisible to SIEM/IR. Flag them all.

    @classmethod
    def find_unlogged_permits(cls, policies: List[Any]) -> List[UnloggedPermitRow]:
        out: List[UnloggedPermitRow] = []
        for p in policies:
            if not p.enabled:
                continue
            if (p.action or "").lower() not in ("accept", "allow", "pass"):
                continue
            log = (p.log_traffic or "").lower()
            if log in ("", "disable", "none"):
                reason = (
                    "Permit rule has no traffic logging — flows matched here are "
                    "invisible to SIEM and incident response."
                )
                out.append(UnloggedPermitRow(rule=p, reason=reason))
        # Sort by permissiveness desc so the most dangerous unlogged permits surface first.
        scores = {row.rule.id: row.score for row in cls.score_permissiveness(policies)}
        out.sort(key=lambda r: -scores.get(r.rule.id, 0))
        return out

    # ── Object hygiene ─────────────────────────────────────────────

    @classmethod
    def object_hygiene(cls, policies: List[Any], addresses: List[Any],
                       services: List[Any]) -> ObjectHygiene:
        # Collect every name referenced anywhere in the rule base. Address
        # groups can also reference other addresses, so include their members.
        ref_addrs: set = set()
        for p in policies:
            ref_addrs.update(_norm_set(p.src_addresses))
            ref_addrs.update(_norm_set(p.dst_addresses))
        for a in addresses:
            if a.kind == "group" and a.members:
                for m in a.members:
                    ref_addrs.add((m or "").strip().lower())

        ref_svcs: set = set()
        for p in policies:
            ref_svcs.update(_norm_set(p.services))
        for s in services:
            if s.protocol == "group" and s.members:
                for m in s.members:
                    ref_svcs.add((m or "").strip().lower())

        unreferenced_addrs = [
            a for a in addresses
            if a.name and a.name.lower() not in ref_addrs
            # Built-in objects with these names are intentionally always-on.
            and a.name.lower() not in {"all", "any", "none"}
        ]
        unreferenced_svcs = [
            s for s in services
            if s.name and s.name.lower() not in ref_svcs
            and s.name.lower() not in {"all", "any", "all_services", "none"}
        ]

        # Duplicate-by-value grouping: two address objects pointing to the
        # same CIDR are a smell — the operator probably forgot they already
        # had one. Skip groups; only flag concrete kinds.
        by_value: Dict[str, List[Any]] = {}
        for a in addresses:
            if a.kind in ("group",):
                continue
            v = (a.value or "").strip()
            if not v:
                continue
            by_value.setdefault(v, []).append(a)
        duplicate_addr_groups = sorted(
            [(v, lst) for v, lst in by_value.items() if len(lst) > 1],
            key=lambda kv: -len(kv[1]),
        )

        return ObjectHygiene(
            total_addrs=len(addresses),
            referenced_addrs=len(addresses) - len(unreferenced_addrs),
            unreferenced_addrs=unreferenced_addrs,
            duplicate_addr_groups=duplicate_addr_groups,
            total_services=len(services),
            referenced_services=len(services) - len(unreferenced_svcs),
            unreferenced_services=unreferenced_svcs,
        )

    # ── Phase 2: log-join widgets (ClickHouse) ─────────────────────
    # All three queries scope by `device_ip` AND a time window. We don't
    # bucket per-policy hit counts ahead of time — at 100M-row scale a
    # single PREWHERE-on-timestamp scan per device returns in <1s in our
    # tests. If volumes grow, materialise into a daily aggregate table.

    @classmethod
    def hits_by_policy(cls, device_ip: str, window_hours: int = 720) -> Dict[str, PolicyHits]:
        """Count log hits per policyname for one device over a window.

        Returns {lowercase policy_name: PolicyHits}. Empty/null policyname is
        excluded — that lives in `implicit_deny_top()`."""
        from ..db.clickhouse import ClickHouseClient
        try:
            client = ClickHouseClient.get_client()
            rows = client.query(f"""
                SELECT policyname,
                       count() AS hits,
                       toString(max(timestamp)) AS last_seen
                FROM syslogs
                PREWHERE timestamp > now() - INTERVAL {int(window_hours)} HOUR
                  AND device_ip = toIPv4('{device_ip}')
                  AND policyname != ''
                GROUP BY policyname
            """).result_rows
        except Exception as e:
            logger.warning(f"hits_by_policy failed for {device_ip}: {e}")
            return {}
        out: Dict[str, PolicyHits] = {}
        for name, hits, last_seen in rows:
            out[(name or "").lower()] = PolicyHits(
                policy_name=name, hits=int(hits), last_seen=last_seen,
            )
        return out

    @classmethod
    def top_talkers_for_policy(cls, device_ip: str, policy_name: str,
                                window_hours: int = 720, limit: int = 10
                                ) -> List[TopTalker]:
        """Top src/dst/dport tuples hitting one specific policy."""
        from ..db.clickhouse import ClickHouseClient
        # Conservative escape — policyname is read from the firewall config
        # (trusted-ish) but we still strip quotes to defang any DSL injection.
        safe = (policy_name or "").replace("'", "")
        try:
            client = ClickHouseClient.get_client()
            rows = client.query(f"""
                SELECT toString(srcip), toString(dstip), dstport, proto, count() AS hits
                FROM syslogs
                PREWHERE timestamp > now() - INTERVAL {int(window_hours)} HOUR
                  AND device_ip = toIPv4('{device_ip}')
                  AND policyname = '{safe}'
                GROUP BY srcip, dstip, dstport, proto
                ORDER BY hits DESC
                LIMIT {int(limit)}
            """).result_rows
        except Exception as e:
            logger.warning(f"top_talkers_for_policy failed: {e}")
            return []
        return [
            TopTalker(srcip=s, dstip=d, dstport=int(p), proto=int(pr), hits=int(h))
            for s, d, p, pr, h in rows
        ]

    # ── Phase 4: zone reachability matrix ──────────────────────────

    @staticmethod
    def _interface_subnet_zones(interfaces: List[Any],
                                  routes: Optional[List[Any]] = None
                                  ) -> List[Tuple[int, int, str]]:
        """Return [(ipv4_lo_int, ipv4_hi_int, zone_label), ...] for IP→zone
        resolution.

        For a transit firewall, directly-connected interface subnets only
        cover a small slice of traffic — most flows come from routed
        networks (BGP/static). We merge the routing table in too: each
        route's destination network carries its egress interface, which
        is exactly the zone label policies reference.

        Sorted longest-prefix first so the lookup picks the most specific
        match (matches what `multiIf` does top-down in ClickHouse).
        """
        import ipaddress
        out: List[Tuple[int, int, str]] = []

        def _add(cidr: str, label: str):
            label = (label or "").strip()
            cidr = (cidr or "").strip()
            if not label or not cidr or cidr in ("0.0.0.0/0", "0.0.0.0"):
                return
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
            except (ValueError, ipaddress.AddressValueError):
                return
            out.append((int(net.network_address), int(net.broadcast_address), label))

        for ifc in interfaces or []:
            label = (getattr(ifc, "zone_name", None)
                     or getattr(ifc, "interface_name", None) or "")
            _add(getattr(ifc, "subnet_cidr", None), label)

        for r in routes or []:
            net = (getattr(r, "network", None) or "").strip()
            iface = (getattr(r, "interface", None) or "").strip()
            if not net or not iface:
                continue
            # `network` may already include the prefix — accept either form.
            if "/" not in net:
                pfx = getattr(r, "prefix_length", None)
                if pfx is None:
                    continue
                net = f"{net}/{pfx}"
            _add(net, iface)

        # Longest-prefix first; on tie, prefer interface routes over default-ish.
        out.sort(key=lambda t: (t[1] - t[0], -len(t[2])))
        # ClickHouse rejects multiIf SQL with >50k AST nodes; each range adds
        # ~5 nodes × 2 fields. Cap at 200 ranges so the generated SQL stays
        # well under that ceiling. With longest-prefix-first ordering we keep
        # the most specific (and so most useful) routes.
        return out[:200]

    @classmethod
    def reachability_matrix(cls, policies: List[Any], interfaces: List[Any],
                            device_ip: Optional[str] = None,
                            window_hours: int = 168,
                            routes: Optional[List[Any]] = None
                            ) -> Optional[ReachabilityMatrix]:
        """Build the src-zone × dst-zone matrix from policies + observed
        traffic. Returns None when neither side has data.

        Cell state legend used by the UI:
          gap            — no permit rule + no observed traffic (intended)
          aligned        — permit rule + traffic flows (working)
          over-provisioned — permit rule but no traffic (cleanup candidate)
          unauthorised   — traffic flows but no permit rule (denied / async)
          denied         — explicit deny rule (not a permit gap)
        """
        cells: Dict[Tuple[str, str], ReachabilityCell] = {}

        # ── Configured side (fast, pure config) ──
        zones_seen: set = set()
        for p in policies or []:
            if not p.enabled:
                continue
            srcs = [z.strip() for z in (p.src_zones or []) if z and z.strip()]
            dsts = [z.strip() for z in (p.dst_zones or []) if z and z.strip()]
            if not srcs or not dsts:
                continue
            is_permit = (p.action or "").lower() in ("accept", "allow", "pass")
            for s in srcs:
                for d in dsts:
                    zones_seen.add(s); zones_seen.add(d)
                    key = (s, d)
                    cell = cells.setdefault(key, ReachabilityCell(src_zone=s, dst_zone=d))
                    if is_permit:
                        cell.rule_count += 1
                    else:
                        cell.deny_rule_count += 1

        # ── Observed side (ClickHouse, optional) ──
        has_observed = False
        if device_ip:
            ranges = cls._interface_subnet_zones(interfaces, routes)
            if ranges:
                has_observed = True
                # Build src/dst CASE expressions in ClickHouse using
                # multiIf — single GROUP BY is way faster than per-pair queries.
                # toUInt32(toIPv4(srcip)) gives us the integer form to range-test.
                def case_expr(field: str) -> str:
                    parts = []
                    for lo, hi, label in ranges:
                        safe = label.replace("'", "")
                        parts.append(f"toUInt32(toIPv4({field})) BETWEEN {lo} AND {hi}, '{safe}'")
                    parts.append("'unknown'")
                    return "multiIf(" + ", ".join(parts) + ")"

                from ..db.clickhouse import ClickHouseClient
                try:
                    client = ClickHouseClient.get_client()
                    # Filter to v4-only rows — some syslog sources mix in
                    # IPv6 link-local addresses that toIPv4() can't parse.
                    rows = client.query(f"""
                        SELECT {case_expr('srcip')} AS src_zone,
                               {case_expr('dstip')} AS dst_zone,
                               count() AS hits
                        FROM syslogs
                        PREWHERE timestamp > now() - INTERVAL {int(window_hours)} HOUR
                          AND device_ip = toIPv4('{device_ip}')
                          AND srcip != '' AND dstip != ''
                          AND match(srcip, '^[0-9.]+$')
                          AND match(dstip, '^[0-9.]+$')
                        GROUP BY src_zone, dst_zone
                        HAVING hits > 0
                    """).result_rows
                    for s, d, h in rows:
                        if not s or not d:
                            continue
                        zones_seen.add(s); zones_seen.add(d)
                        key = (s, d)
                        cell = cells.setdefault(key, ReachabilityCell(src_zone=s, dst_zone=d))
                        cell.observed_hits = int(h)
                except Exception as e:
                    logger.warning(f"reachability_matrix observed query failed: {e}")
                    has_observed = False

        if not cells and not zones_seen:
            return None

        # Classify each cell.
        for cell in cells.values():
            if cell.deny_rule_count and not cell.observed_hits:
                cell.state = "denied"
            elif cell.rule_count and cell.observed_hits:
                cell.state = "aligned"
            elif cell.rule_count and not cell.observed_hits:
                cell.state = "over-provisioned"
            elif not cell.rule_count and cell.observed_hits:
                cell.state = "unauthorised"
            else:
                cell.state = "gap"

        # Stable axis order: alphabetical, then 'unknown' last.
        zones_sorted = sorted(z for z in zones_seen if z != "unknown")
        if "unknown" in zones_seen:
            zones_sorted.append("unknown")

        return ReachabilityMatrix(
            src_zones=zones_sorted,
            dst_zones=zones_sorted,
            cells=cells,
            has_observed=has_observed,
        )

    @classmethod
    def daily_hits_by_policy(cls, device_ip: str, days: int = 30
                              ) -> Dict[str, List[int]]:
        """Per-policy daily hit counts over the last N days.

        Returns {lowercase policy_name: [count_day_-N, ..., count_day_today]}.
        Missing days are filled with 0 so every series has the same length —
        the sparkline / heatmap renderers can iterate without index dancing.
        """
        from ..db.clickhouse import ClickHouseClient
        from datetime import date, timedelta
        try:
            client = ClickHouseClient.get_client()
            rows = client.query(f"""
                SELECT lower(policyname), toDate(timestamp) AS day, count() AS hits
                FROM syslogs
                PREWHERE timestamp > now() - INTERVAL {int(days)} DAY
                  AND device_ip = toIPv4('{device_ip}')
                  AND policyname != ''
                GROUP BY policyname, day
            """).result_rows
        except Exception as e:
            logger.warning(f"daily_hits_by_policy failed for {device_ip}: {e}")
            return {}

        # Build full date axis so every series is the same length (today inclusive).
        today = date.today()
        axis = [today - timedelta(days=days - 1 - i) for i in range(days)]
        idx_for = {d: i for i, d in enumerate(axis)}

        out: Dict[str, List[int]] = {}
        for name, day, hits in rows:
            if name is None:
                continue
            series = out.setdefault(name, [0] * days)
            i = idx_for.get(day)
            if i is not None:
                series[i] = int(hits)
        return out

    @classmethod
    def implicit_deny_top(cls, device_ip: str, window_hours: int = 720,
                          limit: int = 25) -> List[ImplicitDenyRow]:
        """Top denied flows that hit no named policy — these are flows users
        likely WANT and need a rule for. The "missing rule" report.

        Uses lower(action) IN deny-set so we capture deny/drop/block/reset etc.
        across vendors. Skips empty-srcip rows because they're noise from
        UTM/utm sublogs that don't carry the original 5-tuple."""
        from ..db.clickhouse import ClickHouseClient
        try:
            client = ClickHouseClient.get_client()
            rows = client.query(f"""
                SELECT toString(srcip), toString(dstip), dstport, proto, count() AS hits
                FROM syslogs
                PREWHERE timestamp > now() - INTERVAL {int(window_hours)} HOUR
                  AND device_ip = toIPv4('{device_ip}')
                  AND lower(action) IN ('deny','drop','block','reject','blocked','reset-both')
                  AND srcip != ''
                  AND (policyname = '' OR policyname = 'implicit deny' OR policyname IS NULL)
                GROUP BY srcip, dstip, dstport, proto
                ORDER BY hits DESC
                LIMIT {int(limit)}
            """).result_rows
        except Exception as e:
            logger.warning(f"implicit_deny_top failed: {e}")
            return []
        return [
            ImplicitDenyRow(srcip=s, dstip=d, dstport=int(p), proto=int(pr), hits=int(h))
            for s, d, p, pr, h in rows
        ]

    # ── Public entrypoint: compute everything ──────────────────────

    @staticmethod
    def _matrix_to_cache(m: Optional["ReachabilityMatrix"]) -> Optional[Dict[str, Any]]:
        """Serialise just the observed-traffic slice of the matrix so we can
        rebuild it on warm loads without re-running the 57s multiIf query."""
        if m is None:
            return None
        return {
            "has_observed": m.has_observed,
            "observed_cells": [
                {"src": c.src_zone, "dst": c.dst_zone, "hits": c.observed_hits}
                for c in m.cells.values() if c.observed_hits > 0
            ],
        }

    @classmethod
    def _matrix_from_cached(cls, policies: List[Any], cached: Dict[str, Any]
                              ) -> Optional["ReachabilityMatrix"]:
        """Rebuild the matrix from fresh policies + cached observed cells.
        Keeps rule counts fresh while skipping the expensive log query."""
        cells: Dict[Tuple[str, str], ReachabilityCell] = {}
        zones_seen: set = set()

        # Fresh configured side (fast).
        for p in policies or []:
            if not p.enabled:
                continue
            srcs = [z.strip() for z in (p.src_zones or []) if z and z.strip()]
            dsts = [z.strip() for z in (p.dst_zones or []) if z and z.strip()]
            if not srcs or not dsts:
                continue
            is_permit = (p.action or "").lower() in ("accept", "allow", "pass")
            for s in srcs:
                for d in dsts:
                    zones_seen.add(s); zones_seen.add(d)
                    key = (s, d)
                    cell = cells.setdefault(key, ReachabilityCell(src_zone=s, dst_zone=d))
                    if is_permit:
                        cell.rule_count += 1
                    else:
                        cell.deny_rule_count += 1

        # Cached observed overlay.
        for oc in (cached or {}).get("observed_cells", []):
            s, d, h = oc.get("src"), oc.get("dst"), int(oc.get("hits") or 0)
            if not s or not d:
                continue
            zones_seen.add(s); zones_seen.add(d)
            key = (s, d)
            cell = cells.setdefault(key, ReachabilityCell(src_zone=s, dst_zone=d))
            cell.observed_hits = h

        if not cells:
            return None

        for cell in cells.values():
            if cell.deny_rule_count and not cell.observed_hits:
                cell.state = "denied"
            elif cell.rule_count and cell.observed_hits:
                cell.state = "aligned"
            elif cell.rule_count and not cell.observed_hits:
                cell.state = "over-provisioned"
            elif not cell.rule_count and cell.observed_hits:
                cell.state = "unauthorised"
            else:
                cell.state = "gap"

        zones_sorted = sorted(z for z in zones_seen if z != "unknown")
        if "unknown" in zones_seen:
            zones_sorted.append("unknown")
        return ReachabilityMatrix(
            src_zones=zones_sorted, dst_zones=zones_sorted, cells=cells,
            has_observed=(cached or {}).get("has_observed", False),
        )

    # Redis-backed cache for the log-derived parts of the bundle. Keeps the
    # device detail page fast after the first load — pure-config analytics
    # (shadowed/redundant/permissiveness) are always recomputed since they
    # change instantly when a new snapshot is fetched.
    _LOG_CACHE_TTL = 300  # seconds

    @classmethod
    def _cache_key(cls, device_ip: str) -> str:
        # NOTE: cache key is per-device only, NOT per-VDOM. The cached log
        # queries (hits_by_policy, daily_hits, implicit_deny, reachability)
        # all filter by device_ip + timestamp — none of them filter by vdom
        # in their SQL — so the result is identical for any VDOM of the same
        # device. Including vdom here would force a redundant 90s compute
        # on every VDOM switch, which is exactly the bug we just fixed.
        return f"policy_analytics:logs:{device_ip}"

    @classmethod
    def _load_log_cache(cls, device_ip: str) -> Optional[Dict[str, Any]]:
        try:
            import redis as _redis
            r = _redis.Redis(host="localhost", port=6379, decode_responses=True)
            raw = r.get(cls._cache_key(device_ip))
            if not raw:
                return None
            import json as _json
            return _json.loads(raw)
        except Exception:
            return None

    @classmethod
    def _store_log_cache(cls, device_ip: str, payload: Dict[str, Any]):
        try:
            import redis as _redis
            r = _redis.Redis(host="localhost", port=6379, decode_responses=True)
            import json as _json
            r.setex(cls._cache_key(device_ip), cls._LOG_CACHE_TTL, _json.dumps(payload))
        except Exception as e:
            logger.warning(f"log-cache write failed: {e}")

    @classmethod
    def invalidate_log_cache(cls, device_ip: str, vdom: Optional[str] = None):
        """Called after a fetch so the next page load sees fresh data.
        `vdom` is accepted for API compatibility but ignored — the cache is
        per-device, not per-VDOM."""
        try:
            import redis as _redis
            r = _redis.Redis(host="localhost", port=6379, decode_responses=True)
            r.delete(cls._cache_key(device_ip))
        except Exception:
            pass

    @classmethod
    def compute(cls, policies: List[Any], addresses: List[Any],
                services: List[Any],
                device_ip: Optional[str] = None,
                log_window_hours: int = 720,
                interfaces: Optional[List[Any]] = None,
                routes: Optional[List[Any]] = None,
                vdom: Optional[str] = None,
                use_cache: bool = True) -> PolicyAnalyticsBundle:
        """Compute the full bundle.

        If `device_ip` is provided, also run the log-join queries (Phase 2:
        hits_by_policy, zero-hit detection, implicit-deny spotlight).
        If `interfaces` is provided, also build the Phase 4 zone reachability
        matrix (configured-vs-observed). Both are independent — passing one
        without the other still works.
        """
        if not policies:
            return PolicyAnalyticsBundle(
                kpi_active_rules=0, kpi_disabled_rules=0,
                kpi_shadowed_count=0, kpi_redundant_count=0,
                kpi_unlogged_permits=0,
                kpi_avg_permissiveness=0, kpi_critical_permissiveness=0,
                kpi_unreferenced_objects=0,
                shadowed=[], redundant=[], permissiveness=[],
                unlogged_permits=[],
                object_hygiene=cls.object_hygiene([], addresses, services),
            )

        shadowed, redundant = cls.find_shadowed_and_redundant(policies)
        permissiveness = cls.score_permissiveness(policies)
        unlogged = cls.find_unlogged_permits(policies)
        hygiene = cls.object_hygiene(policies, addresses, services)

        active = sum(1 for p in policies if p.enabled)
        avg_perm = (sum(r.score for r in permissiveness) // len(permissiveness)) if permissiveness else 0
        crit = sum(1 for r in permissiveness if r.band == "critical")

        # Phase 2 — log-join (no-op when device_ip is None or query fails).
        # The four log queries below can easily total 90s on a busy device
        # (reachability multiIf alone is ~57s), so we cache the results per
        # device+vdom. Config-only widgets always recompute because they're
        # cheap and must reflect the latest snapshot immediately.
        hits_by_name: Dict[str, PolicyHits] = {}
        zero_hit: List[Any] = []
        implicit_deny: List[ImplicitDenyRow] = []
        daily_hits: Dict[str, List[int]] = {}
        total_hits = 0
        reachability_cached = None
        cache_hit = False

        if device_ip and use_cache:
            cached = cls._load_log_cache(device_ip)
            if cached:
                cache_hit = True
                hits_by_name = {
                    k: PolicyHits(**v) for k, v in cached.get("hits_by_name", {}).items()
                }
                implicit_deny = [
                    ImplicitDenyRow(**r) for r in cached.get("implicit_deny", [])
                ]
                daily_hits = cached.get("daily_hits", {})
                total_hits = cached.get("total_hits", 0)
                reachability_cached = cached.get("reachability")

        if device_ip and not cache_hit:
            hits_by_name = cls.hits_by_policy(device_ip, window_hours=log_window_hours)
            implicit_deny = cls.implicit_deny_top(device_ip, window_hours=log_window_hours)
            total_hits = sum(h.hits for h in hits_by_name.values())
            daily_hits = cls.daily_hits_by_policy(
                device_ip, days=max(1, log_window_hours // 24),
            )

        # Zero-hit derivation uses the freshest policy list — not cached.
        if device_ip:
            for p in policies:
                if not p.enabled:
                    continue
                key = (p.name or p.rule_id or "").lower()
                if key and key not in hits_by_name:
                    zero_hit.append(p)

        # Phase 4 — zone reachability. If we have a cache hit, build the
        # matrix from cached observed hits; otherwise run the live query.
        if cache_hit and reachability_cached is not None:
            reachability = cls._matrix_from_cached(
                policies, reachability_cached,
            )
        else:
            reachability = cls.reachability_matrix(
                policies, interfaces or [], device_ip=device_ip,
                window_hours=min(log_window_hours, 168),
                routes=routes or [],
            )

        # Persist freshly-computed log fields so the next page load is fast.
        if device_ip and not cache_hit:
            try:
                cls._store_log_cache(device_ip, {
                    "hits_by_name": {
                        k: {"policy_name": v.policy_name, "hits": v.hits, "last_seen": v.last_seen}
                        for k, v in hits_by_name.items()
                    },
                    "implicit_deny": [
                        {"srcip": r.srcip, "dstip": r.dstip, "dstport": r.dstport,
                         "proto": r.proto, "hits": r.hits} for r in implicit_deny
                    ],
                    "daily_hits": daily_hits,
                    "total_hits": total_hits,
                    "reachability": cls._matrix_to_cache(reachability),
                })
            except Exception as e:
                logger.warning(f"analytics cache store failed: {e}")

        return PolicyAnalyticsBundle(
            kpi_active_rules=active,
            kpi_disabled_rules=len(policies) - active,
            kpi_shadowed_count=len(shadowed),
            kpi_redundant_count=len(redundant),
            kpi_unlogged_permits=len(unlogged),
            kpi_avg_permissiveness=avg_perm,
            kpi_critical_permissiveness=crit,
            kpi_unreferenced_objects=len(hygiene.unreferenced_addrs) + len(hygiene.unreferenced_services),
            kpi_zero_hit_30d=len(zero_hit),
            kpi_total_hits_30d=total_hits,
            shadowed=shadowed,
            redundant=redundant,
            permissiveness=permissiveness,
            unlogged_permits=unlogged,
            object_hygiene=hygiene,
            hits_by_name=hits_by_name,
            zero_hit_rules=zero_hit,
            implicit_deny=implicit_deny,
            log_window_hours=log_window_hours if device_ip else 0,
            daily_hits=daily_hits,
            daily_window_days=(log_window_hours // 24) if device_ip else 0,
            reachability=reachability,
        )
