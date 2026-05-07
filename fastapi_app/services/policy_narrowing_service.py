"""
PolicyNarrowingService — Learning Mode (L1 Observe + L2 Suggest).

Given an existing firewall policy on a device that is suspected to be too
broad (e.g. ``Allow_LAN_to_Any``), correlate observed traffic that matched
that policy and propose a set of narrower replacement rules that together
cover most of the real traffic. Anything left over is surfaced as a
"residual" so the analyst can decide whether it is a missing legitimate
flow or a sketchy one that should not have been allowed.

Two phases delivered here:

  L1 (Observe)  — clustered view of matched traffic, no rule generation.
  L2 (Suggest)  — ranked candidate rules + uncovered residuals + export.

Phases L3-L5 (shadow/replay/promote) are explicitly out of scope; this
service is read-only and never pushes to the firewall.

Source of truth: ClickHouse ``syslogs`` table, joined to policies by the
``policyname`` column (Fortinet ``policyname`` / Palo Alto ``rule``,
already normalised by the parser).
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# IANA → label. Anything else lands in "other".
_PROTO_LABEL = {6: "tcp", 17: "udp", 1: "icmp"}

# Service grouping used when building suggested rules. Folds a tuple of
# common ports into a single named service so we don't emit 14 nearly
# identical rules. Tuned for typical FortiGate / PAN service objects.
_SERVICE_GROUPS: List[Tuple[str, frozenset]] = [
    ("web",        frozenset({(6, 80), (6, 443), (6, 8080), (6, 8443)})),
    ("dns",        frozenset({(17, 53), (6, 53)})),
    ("ldap",       frozenset({(6, 389), (6, 636), (17, 389)})),
    ("smb",        frozenset({(6, 445), (6, 139), (17, 137), (17, 138)})),
    ("rdp",        frozenset({(6, 3389)})),
    ("ssh",        frozenset({(6, 22)})),
    ("kerberos",   frozenset({(6, 88), (17, 88), (6, 464), (17, 464)})),
    ("ntp",        frozenset({(17, 123)})),
    ("snmp",       frozenset({(17, 161), (17, 162)})),
    ("mail",       frozenset({(6, 25), (6, 465), (6, 587), (6, 110), (6, 995),
                              (6, 143), (6, 993)})),
]

# Privileged ports that bump risk in the residual ranking. Also used to
# warn when a candidate inherits one of these.
_RISKY_PORTS: frozenset = frozenset({
    22, 23, 3389, 5985, 5986,            # admin
    445, 139, 137, 138,                  # smb
    1433, 3306, 5432, 1521, 27017,       # databases
    21, 69,                              # ftp/tftp
    161, 162,                            # snmp
})

# Minimum thresholds before a cluster is promoted to a candidate (vs
# residual). Cheap heuristics — easy to tune from caller.
DEFAULT_MIN_HITS_FOR_CANDIDATE = 5
DEFAULT_MIN_DISTINCT_DAYS_FOR_CANDIDATE = 1
DEFAULT_RESIDUAL_LIMIT = 50


# ─────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────


@dataclass
class FlowRow:
    """One observed (src, dst, port, proto) flow that matched the policy."""
    srcip: str
    dstip: str
    dstport: int
    proto: int
    src_zone: str
    dst_zone: str
    application: str
    hits: int
    distinct_days: int
    distinct_severity_high: int  # count where severity <= 4
    first_seen: Optional[str]
    last_seen: Optional[str]


@dataclass
class RuleCandidate:
    """A proposed narrower rule that would have allowed a chunk of the
    observed traffic. Lists are kept human-friendly (names + IP literals);
    the caller maps these to address/service objects when applying."""
    label: str                              # "LAN → DC: web"
    src_zones: List[str]
    dst_zones: List[str]
    src_ips: List[str]                      # may be CIDR strings after subnet rollup
    dst_ips: List[str]
    proto: str                              # tcp / udp / icmp / mixed
    ports: List[int]
    service_group: Optional[str]            # "web", "ldap", … or None
    applications: List[str]
    hits: int
    distinct_src: int
    distinct_dst: int
    coverage_pct: float                     # share of original-policy hits
    confidence: float                       # 0..100
    risk_flags: List[str]                   # ["privileged-port", "cross-zone-rdp"]
    sample_flows: List[Dict[str, Any]]      # up to N raw flow rows for evidence


@dataclass
class ResidualFlow:
    """A flow that no candidate covers, surfaced for analyst review."""
    srcip: str
    dstip: str
    dstport: int
    proto: str
    application: str
    hits: int
    risk: str                               # 'high' | 'medium' | 'low'
    risk_reasons: List[str]


@dataclass
class NarrowingReport:
    device_ip: str
    policy_name: str
    window_days: int
    total_hits: int
    distinct_flows: int
    distinct_src: int
    distinct_dst: int
    candidates: List[RuleCandidate]
    residuals: List[ResidualFlow]
    coverage_pct: float                     # sum of candidate coverage
    notes: List[str]                        # human messages (e.g. "no traffic")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_ip": self.device_ip,
            "policy_name": self.policy_name,
            "window_days": self.window_days,
            "total_hits": self.total_hits,
            "distinct_flows": self.distinct_flows,
            "distinct_src": self.distinct_src,
            "distinct_dst": self.distinct_dst,
            "coverage_pct": self.coverage_pct,
            "candidates": [asdict(c) for c in self.candidates],
            "residuals": [asdict(r) for r in self.residuals],
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _proto_label(p: int) -> str:
    return _PROTO_LABEL.get(int(p), f"proto-{int(p)}")


def _service_group_for(port_proto_pairs: frozenset) -> Optional[str]:
    """Return the named service group whose port-tuple is a superset of the
    observed pairs, else None. We require the *observed* pairs to be a
    subset of the group, so emitting "web" only happens when every
    observed flow is actually web."""
    for name, group in _SERVICE_GROUPS:
        if port_proto_pairs and port_proto_pairs.issubset(group):
            return name
    return None


def _try_subnet_rollup(ips: List[str], min_coverage: float = 0.6) -> List[str]:
    """If a clean majority of the IPs fall in a /24 (or /16), collapse to
    that CIDR. Otherwise return the original list unchanged.

    This is intentionally simple — we don't try to learn arbitrary
    prefix lengths. /24 covers most internal-network cases; /16 catches
    multi-VLAN deployments. Anything weirder stays as raw IPs.
    """
    if len(ips) < 4:
        return ips
    parsed: List[ipaddress.IPv4Address] = []
    for ip in ips:
        try:
            parsed.append(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError):
            continue
    if not parsed:
        return ips

    for prefix in (24, 16):
        buckets: Dict[str, int] = defaultdict(int)
        for ip in parsed:
            net = ipaddress.IPv4Network((int(ip) & (0xFFFFFFFF << (32 - prefix)),
                                          prefix))
            buckets[str(net)] += 1
        if not buckets:
            continue
        top_net, top_count = max(buckets.items(), key=lambda kv: kv[1])
        if top_count / len(parsed) >= min_coverage and top_count >= 4:
            # Roll up — keep the dominant CIDR plus any outlier IPs as-is.
            outlier_ips = [
                str(ip) for ip in parsed
                if ip not in ipaddress.IPv4Network(top_net)
            ]
            return [top_net] + sorted(set(outlier_ips))
    return ips


def _confidence(hits: int, distinct_src: int, distinct_days: int,
                window_days: int) -> float:
    """Confidence 0..100. Heuristic — not a probability.
    log(hits) brings high-volume flows to ~mid-range; distinct_src and
    distinct_days reward breadth (one host pinging once is weak signal)."""
    if hits <= 0:
        return 0.0
    h = min(40.0, math.log10(max(hits, 1)) * 12.0)
    s = min(30.0, math.log2(max(distinct_src, 1) + 1) * 10.0)
    d = min(30.0, (distinct_days / max(window_days, 1)) * 30.0)
    return round(h + s + d, 1)


def _candidate_risk_flags(proto: int, ports: List[int],
                          src_zone: str, dst_zone: str) -> List[str]:
    flags: List[str] = []
    if any(p in _RISKY_PORTS for p in ports):
        flags.append("privileged-port")
    if proto == 6 and 3389 in ports and src_zone != dst_zone:
        flags.append("cross-zone-rdp")
    if proto == 6 and 22 in ports and src_zone != dst_zone:
        flags.append("cross-zone-ssh")
    if proto == 6 and (445 in ports or 139 in ports) and src_zone != dst_zone:
        flags.append("cross-zone-smb")
    return flags


def _residual_risk(flow: FlowRow) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    score = 0
    if flow.dstport in _RISKY_PORTS:
        score += 2
        reasons.append(f"privileged port {flow.dstport}")
    if flow.distinct_severity_high > 0:
        score += 2
        reasons.append("high-severity events")
    if flow.src_zone and flow.dst_zone and flow.src_zone != flow.dst_zone:
        score += 1
        reasons.append("cross-zone")
    # Public destination (very rough heuristic — not RFC1918)
    try:
        d = ipaddress.IPv4Address(flow.dstip)
        if not d.is_private and not d.is_loopback and not d.is_multicast:
            score += 1
            reasons.append("public destination")
    except (ipaddress.AddressValueError, ValueError):
        pass
    if score >= 3:
        return ("high", reasons)
    if score >= 1:
        return ("medium", reasons)
    return ("low", reasons or ["no risk indicators"])


# ─────────────────────────────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────────────────────────────


class PolicyNarrowingService:
    """Compute a NarrowingReport for one policy on one device.

    Stateless. Single entrypoint: ``analyze(...)``.
    """

    @classmethod
    def analyze(
        cls,
        device_ip: str,
        policy_name: str,
        window_days: int = 30,
        min_hits: int = DEFAULT_MIN_HITS_FOR_CANDIDATE,
        residual_limit: int = DEFAULT_RESIDUAL_LIMIT,
    ) -> NarrowingReport:
        # Defensive defaults — empty policy_name would match every implicit
        # deny in the table and produce nonsense output.
        if not policy_name or not policy_name.strip():
            return NarrowingReport(
                device_ip=device_ip, policy_name=policy_name or "",
                window_days=window_days,
                total_hits=0, distinct_flows=0, distinct_src=0, distinct_dst=0,
                candidates=[], residuals=[], coverage_pct=0.0,
                notes=["No policy name provided."],
            )

        flows = cls._fetch_flows(device_ip, policy_name, window_days)
        if not flows:
            return NarrowingReport(
                device_ip=device_ip, policy_name=policy_name,
                window_days=window_days,
                total_hits=0, distinct_flows=0, distinct_src=0, distinct_dst=0,
                candidates=[], residuals=[], coverage_pct=0.0,
                notes=[f"No traffic matched '{policy_name}' in the last "
                       f"{window_days} day(s). The rule may be unused or the "
                       f"name in syslogs may differ from the configured rule."],
            )

        total_hits = sum(f.hits for f in flows)
        distinct_src = len({f.srcip for f in flows if f.srcip})
        distinct_dst = len({f.dstip for f in flows if f.dstip})

        # ── Cluster on (src_zone, dst_zone, proto, service-group-or-port) ──
        # This is the L2 grouping. We deliberately don't cluster down to the
        # IP level here — that's exposed inside each candidate as src_ips/dst_ips.
        clusters: Dict[Tuple[str, str, int, frozenset], List[FlowRow]] = defaultdict(list)
        for f in flows:
            # Attempt service-group rollup at the cluster level — if all
            # flows in the bucket share a known service, we surface that;
            # otherwise the cluster keeps its raw port set.
            key = (f.src_zone or "", f.dst_zone or "",
                   int(f.proto), frozenset({(int(f.proto), int(f.dstport))}))
            clusters[key].append(f)

        # Now collapse single-port clusters in the same zone/proto into
        # service-group clusters when the union of their ports matches a
        # known group exactly. This is what produces "web" instead of
        # "tcp/80, tcp/443, tcp/8080" as three separate candidates.
        clusters = cls._merge_into_service_groups(clusters)

        candidates: List[RuleCandidate] = []
        used_flow_ids: set = set()

        for key, bucket in clusters.items():
            cluster_hits = sum(f.hits for f in bucket)
            if cluster_hits < min_hits:
                continue
            distinct_src_in = len({f.srcip for f in bucket if f.srcip})
            distinct_dst_in = len({f.dstip for f in bucket if f.dstip})
            distinct_days = max((f.distinct_days for f in bucket), default=1)
            if distinct_days < DEFAULT_MIN_DISTINCT_DAYS_FOR_CANDIDATE:
                continue

            src_ips = sorted({f.srcip for f in bucket if f.srcip})
            dst_ips = sorted({f.dstip for f in bucket if f.dstip})
            src_ips_rolled = _try_subnet_rollup(src_ips)
            dst_ips_rolled = _try_subnet_rollup(dst_ips)
            ports = sorted({int(f.dstport) for f in bucket})
            apps = sorted({f.application for f in bucket if f.application})

            port_proto_pairs = frozenset({(int(f.proto), int(f.dstport)) for f in bucket})
            sg = _service_group_for(port_proto_pairs)
            protos = {int(f.proto) for f in bucket}
            proto_label = (_proto_label(next(iter(protos))) if len(protos) == 1
                           else "mixed")

            src_zone = key[0] or "(unknown)"
            dst_zone = key[1] or "(unknown)"
            label = (
                f"{src_zone} → {dst_zone}: "
                f"{sg or (','.join(str(p) for p in ports[:4]) + ('…' if len(ports) > 4 else ''))}"
                f" ({proto_label})"
            )

            cov_pct = round((cluster_hits / total_hits) * 100.0, 2) if total_hits else 0.0
            conf = _confidence(cluster_hits, distinct_src_in, distinct_days, window_days)
            risk_flags = _candidate_risk_flags(
                next(iter(protos)) if len(protos) == 1 else 0,
                ports, src_zone, dst_zone,
            )

            # Evidence — top 5 contributing flows by hits
            sample = sorted(bucket, key=lambda f: -f.hits)[:5]
            sample_flows = [
                {
                    "srcip": s.srcip, "dstip": s.dstip,
                    "dstport": s.dstport, "proto": _proto_label(s.proto),
                    "application": s.application,
                    "hits": s.hits,
                    "first_seen": s.first_seen, "last_seen": s.last_seen,
                }
                for s in sample
            ]

            candidates.append(RuleCandidate(
                label=label,
                src_zones=[src_zone] if src_zone != "(unknown)" else [],
                dst_zones=[dst_zone] if dst_zone != "(unknown)" else [],
                src_ips=src_ips_rolled,
                dst_ips=dst_ips_rolled,
                proto=proto_label,
                ports=ports,
                service_group=sg,
                applications=apps,
                hits=cluster_hits,
                distinct_src=distinct_src_in,
                distinct_dst=distinct_dst_in,
                coverage_pct=cov_pct,
                confidence=conf,
                risk_flags=risk_flags,
                sample_flows=sample_flows,
            ))

            for f in bucket:
                used_flow_ids.add(id(f))

        # Residuals: flows that no candidate covers (small clusters or one-offs).
        residuals_raw: List[FlowRow] = [f for f in flows if id(f) not in used_flow_ids]
        # Sort by risk first (high port/severity), then hits.
        scored: List[Tuple[FlowRow, str, List[str]]] = []
        for f in residuals_raw:
            risk, reasons = _residual_risk(f)
            scored.append((f, risk, reasons))
        rank = {"high": 0, "medium": 1, "low": 2}
        scored.sort(key=lambda x: (rank[x[1]], -x[0].hits))

        residuals: List[ResidualFlow] = [
            ResidualFlow(
                srcip=f.srcip, dstip=f.dstip,
                dstport=f.dstport, proto=_proto_label(f.proto),
                application=f.application or "",
                hits=f.hits,
                risk=risk, risk_reasons=reasons,
            )
            for f, risk, reasons in scored[:residual_limit]
        ]

        # Sort candidates: coverage desc, then confidence desc.
        candidates.sort(key=lambda c: (-c.coverage_pct, -c.confidence))
        coverage_total = round(sum(c.coverage_pct for c in candidates), 2)

        notes: List[str] = []
        if coverage_total < 80.0 and total_hits > 0:
            notes.append(
                f"Candidates cover only {coverage_total:.1f}% of traffic — "
                f"the rule may be carrying highly heterogeneous flows. "
                f"Review the residuals before narrowing."
            )
        if not candidates and total_hits > 0:
            notes.append(
                f"No flow cluster reached the minimum-hit threshold "
                f"({min_hits}). All traffic is in the residual list — "
                f"consider lowering the threshold or extending the window."
            )

        return NarrowingReport(
            device_ip=device_ip,
            policy_name=policy_name,
            window_days=window_days,
            total_hits=total_hits,
            distinct_flows=len(flows),
            distinct_src=distinct_src,
            distinct_dst=distinct_dst,
            candidates=candidates,
            residuals=residuals,
            coverage_pct=coverage_total,
            notes=notes,
        )

    # ── Internals ──────────────────────────────────────────────────

    @classmethod
    def _fetch_flows(cls, device_ip: str, policy_name: str,
                     window_days: int) -> List[FlowRow]:
        """Pull aggregated flows that matched ``policy_name`` from ClickHouse.

        We aggregate at (srcip, dstip, dstport, proto, src_zone, dst_zone,
        application) so a 30-day analysis stays bounded even on a busy
        policy. ``severity <= 4`` corresponds to RFC 5424 0..4 (emerg →
        warning) — we count those separately to flag risk in the residual.
        """
        from ..db.clickhouse import ClickHouseClient
        # The policyname column is LowCardinality(String); we still single-quote
        # the value defensively against names containing apostrophes.
        safe_name = (policy_name or "").replace("'", "''")
        # Window can't be negative; cap at 90 days to keep memory bounded.
        days = max(1, min(int(window_days), 90))

        try:
            client = ClickHouseClient.get_client()
            rows = client.query(f"""
                SELECT
                    srcip, dstip, dstport, proto,
                    any(src_zone) AS src_zone,
                    any(dst_zone) AS dst_zone,
                    any(application) AS application,
                    sum(1) AS hits,
                    uniqExact(toDate(timestamp)) AS distinct_days,
                    countIf(severity <= 4) AS sev_high,
                    formatDateTime(min(timestamp), '%Y-%m-%d %H:%M:%S') AS first_seen,
                    formatDateTime(max(timestamp), '%Y-%m-%d %H:%M:%S') AS last_seen
                FROM syslogs
                WHERE device_ip = toIPv4('{device_ip}')
                  AND timestamp >= now() - INTERVAL {days} DAY
                  AND policyname = '{safe_name}'
                  AND srcip != ''
                  AND dstip != ''
                GROUP BY srcip, dstip, dstport, proto
                ORDER BY hits DESC
                LIMIT 5000
            """).result_rows
        except Exception as e:
            logger.warning(f"PolicyNarrowing _fetch_flows failed for "
                           f"{device_ip}/{policy_name}: {e}")
            return []

        out: List[FlowRow] = []
        for r in rows:
            (srcip, dstip, dstport, proto, src_zone, dst_zone, app,
             hits, distinct_days, sev_high, first_seen, last_seen) = r
            out.append(FlowRow(
                srcip=str(srcip or ""),
                dstip=str(dstip or ""),
                dstport=int(dstport or 0),
                proto=int(proto or 0),
                src_zone=str(src_zone or ""),
                dst_zone=str(dst_zone or ""),
                application=str(app or ""),
                hits=int(hits or 0),
                distinct_days=int(distinct_days or 0),
                distinct_severity_high=int(sev_high or 0),
                first_seen=str(first_seen) if first_seen else None,
                last_seen=str(last_seen) if last_seen else None,
            ))
        return out

    @classmethod
    def _merge_into_service_groups(
        cls,
        clusters: Dict[Tuple[str, str, int, frozenset], List[FlowRow]],
    ) -> Dict[Tuple[str, str, int, frozenset], List[FlowRow]]:
        """Take per-port clusters in the same zone-pair / proto and try to
        merge them into a single cluster keyed by service-group when the
        union of their ports matches a known group.

        The result still uses the same key shape; the frozenset is replaced
        with the group's port set so subsequent code can ask for the
        service name once.
        """
        # Bucket by (src_zone, dst_zone, proto)
        by_zone_proto: Dict[Tuple[str, str, int], List[Tuple[frozenset, List[FlowRow]]]] = defaultdict(list)
        for key, bucket in clusters.items():
            by_zone_proto[(key[0], key[1], key[2])].append((key[3], bucket))

        out: Dict[Tuple[str, str, int, frozenset], List[FlowRow]] = {}
        for (sz, dz, proto), entries in by_zone_proto.items():
            # Try every service group: do the entries' ports fit?
            merged_into_group: set = set()
            for name, group in _SERVICE_GROUPS:
                # Collect entries whose single port belongs to this group
                matching: List[Tuple[frozenset, List[FlowRow]]] = []
                for ports, bucket in entries:
                    if ports.issubset(group):
                        matching.append((ports, bucket))
                # Require at least 2 entries before we merge — otherwise
                # we'd just be relabelling a single port as a group.
                if len(matching) < 2:
                    continue
                merged_bucket: List[FlowRow] = []
                merged_ports: frozenset = frozenset()
                for ports, bucket in matching:
                    merged_bucket.extend(bucket)
                    merged_ports = merged_ports | ports
                    merged_into_group.add(ports)
                out[(sz, dz, proto, merged_ports)] = merged_bucket
            # Anything not folded into a group keeps its original key.
            for ports, bucket in entries:
                if ports in merged_into_group:
                    continue
                out[(sz, dz, proto, ports)] = bucket
        return out
