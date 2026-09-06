"""
NQL Schema & Suggestion Engine.

Powers the generic, FortiGate/FortiAnalyzer-style search bar on the Log Explorer:
as the user types, we work out *where the cursor is* inside the query and offer
the right completions — field names, operators, live field values pulled from
ClickHouse, boolean keywords, or pipeline commands.

Three layers of field knowledge:

  1. CURATED   — native `syslogs` columns and well-known vendor aliases, each with
                 a type, category and human description (this file).
  2. DYNAMIC   — every key present in the `parsed_data` map of recent logs,
                 discovered from ClickHouse and cached. This is what makes the
                 search "generic": any field any parser has ever emitted becomes
                 searchable and suggestible without a code change.
  3. VALUES    — top-N actual values for the field being typed, counted over the
                 explorer's current time window.
"""

from __future__ import annotations

import re
import time
import logging
import threading
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Any identifier interpolated into SQL must match this. Everything else is
# rejected before it reaches ClickHouse.
IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

_DEVICE_EXPR = "if(vdom != '', concat(toString(device_ip), '_', vdom), toString(device_ip))"


# ============================================================
# Curated field catalog
# ============================================================

@dataclass
class NQLField:
    name: str
    type: str                       # ip | port | number | bytes | duration | enum | string | text | datetime
    description: str
    category: str
    expr: Optional[str] = None      # SQL expression yielding the value (String-castable)
    aliases: Tuple[str, ...] = ()
    values: Tuple[str, ...] = ()    # static fallback values for enum-ish fields
    example: str = ""
    suggest_values: bool = True     # offer live value completion for this field

    def value_expr(self) -> str:
        return self.expr or f"toString({self.name})"


def _f(*args, **kwargs) -> NQLField:
    return NQLField(*args, **kwargs)


CURATED_FIELDS: List[NQLField] = [
    # ── Network ──────────────────────────────────────────────
    _f("srcip", "ip", "Source IP address", "Network", expr="srcip",
       aliases=("src_ip", "source_ip"), example="srcip:10.0.0.0/8"),
    _f("dstip", "ip", "Destination IP address", "Network", expr="dstip",
       aliases=("dst_ip", "destination_ip"), example="dstip:8.8.8.8"),
    _f("srcport", "port", "Source port", "Network", expr="toString(srcport)",
       aliases=("src_port",), example="srcport:>1024"),
    _f("dstport", "port", "Destination port", "Network", expr="toString(dstport)",
       aliases=("dst_port",), example="dstport:443"),
    _f("proto", "number", "IP protocol number (6=TCP, 17=UDP, 1=ICMP)", "Network",
       expr="toString(proto)", aliases=("protocol",), example="proto:6"),
    _f("service", "string", "Service / destination service name", "Network", expr="service",
       example="service:HTTPS"),
    _f("src_intf", "string", "Ingress interface", "Network", expr="src_intf",
       aliases=("srcintf", "inbound_if"), example="src_intf:port1"),
    _f("dst_intf", "string", "Egress interface", "Network", expr="dst_intf",
       aliases=("dstintf", "outbound_if"), example="dst_intf:wan1"),
    _f("src_zone", "string", "Source zone", "Network", expr="src_zone",
       aliases=("srczone",), example="src_zone:trust"),
    _f("dst_zone", "string", "Destination zone", "Network", expr="dst_zone",
       aliases=("dstzone",), example="dst_zone:untrust"),
    _f("nat_srcip", "ip", "NAT'd source IP", "Network",
       expr="if(parsed_data['nat_srcip'] != '', parsed_data['nat_srcip'], parsed_data['nat_src_ip'])",
       aliases=("nat_src_ip", "transip"), example="nat_srcip:203.0.113.5"),
    _f("nat_dstip", "ip", "NAT'd destination IP", "Network",
       expr="if(parsed_data['nat_dstip'] != '', parsed_data['nat_dstip'], parsed_data['nat_dst_ip'])",
       aliases=("nat_dst_ip",), example="nat_dstip:10.1.1.10"),

    # ── Geo ──────────────────────────────────────────────────
    _f("src_country", "string", "Source country", "Geo", expr="src_country",
       aliases=("srccountry", "src_location"), example="src_country:China"),
    _f("dst_country", "string", "Destination country", "Geo", expr="dst_country",
       aliases=("dstcountry", "dst_location"), example="dst_country:Russia"),

    # ── Policy ───────────────────────────────────────────────
    _f("action", "enum", "Session action taken by the firewall", "Policy", expr="action",
       values=("accept", "allow", "deny", "drop", "close", "timeout", "start", "block", "reset"),
       example="action:deny"),
    _f("policyname", "string", "Firewall policy / rule name", "Policy", expr="policyname",
       aliases=("rule", "policy"), example='policyname:"Allow Web"'),
    _f("policyid", "number", "Firewall policy ID", "Policy", expr="parsed_data['policyid']",
       example="policyid:12"),
    _f("policytype", "string", "Policy type", "Policy", expr="parsed_data['policytype']"),

    # ── Application ──────────────────────────────────────────
    _f("application", "string", "Application name", "Application", expr="application",
       aliases=("app",), example="application:HTTPS"),
    _f("appcat", "string", "Application category", "Application",
       expr="if(parsed_data['appcat'] != '', parsed_data['appcat'], parsed_data['category_of_app'])",
       aliases=("category_of_app", "app_subcat"), example="appcat:Video/Audio"),
    _f("apprisk", "string", "Application risk rating", "Application", expr="parsed_data['apprisk']",
       aliases=("risk_of_app",), example="apprisk:high"),
    _f("url", "text", "Requested URL", "Application", expr="parsed_data['url']",
       example="url:~login"),
    _f("hostname", "string", "HTTP host / server name", "Application", expr="parsed_data['hostname']",
       example="hostname:~example.com"),
    _f("httpmethod", "enum", "HTTP method", "Application", expr="parsed_data['httpmethod']",
       values=("GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT")),
    _f("agent", "text", "HTTP user agent", "Application", expr="parsed_data['agent']"),
    _f("qname", "string", "DNS query name", "Application", expr="parsed_data['qname']",
       example="qname:~malware"),
    _f("qtype", "string", "DNS query type", "Application", expr="parsed_data['qtype']"),

    # ── Threat / UTM ─────────────────────────────────────────
    _f("threat_id", "string", "Threat / IPS signature ID", "Threat", expr="threat_id",
       example="threat_id:30845"),
    _f("threat_category", "string", "Threat category", "Threat", expr="parsed_data['threat_category']"),
    _f("threat_severity", "string", "Threat severity", "Threat", expr="parsed_data['threat_severity']"),
    _f("crlevel", "enum", "Client reputation level", "Threat", expr="parsed_data['crlevel']",
       values=("low", "medium", "high", "critical")),
    _f("crscore", "number", "Client reputation score", "Threat", expr="parsed_data['crscore']"),
    _f("utmaction", "string", "UTM action", "Threat", expr="parsed_data['utmaction']"),
    _f("cat", "string", "Web filter category ID", "Threat", expr="parsed_data['cat']"),
    _f("catdesc", "string", "Web filter category name", "Threat", expr="parsed_data['catdesc']",
       example='catdesc:"Malicious Websites"'),
    _f("eventtype", "string", "Event subtype (UTM/event logs)", "Threat", expr="parsed_data['eventtype']"),
    _f("profile", "string", "UTM profile name", "Threat", expr="parsed_data['profile']"),

    # ── Identity ─────────────────────────────────────────────
    _f("src_user", "string", "Authenticated source user", "Identity", expr="src_user",
       aliases=("srcuser", "user"), example="src_user:jdoe"),
    _f("dstuser", "string", "Destination user", "Identity", expr="parsed_data['dstuser']",
       aliases=("dst_user",)),
    _f("unauthuser", "string", "Unauthenticated user", "Identity", expr="parsed_data['unauthuser']"),
    _f("group", "string", "User group", "Identity", expr="parsed_data['group']"),
    _f("srcname", "string", "Source host name", "Identity", expr="parsed_data['srcname']"),
    _f("srcmac", "string", "Source MAC address", "Identity", expr="parsed_data['srcmac']"),
    _f("dstmac", "string", "Destination MAC address", "Identity", expr="parsed_data['dstmac']"),
    _f("devtype", "string", "Source device type", "Identity", expr="parsed_data['devtype']"),
    _f("osname", "string", "Source OS name", "Identity", expr="parsed_data['osname']"),

    # ── Session / volume ─────────────────────────────────────
    _f("session_id", "number", "Session ID", "Session", expr="toString(session_id)",
       aliases=("sessionid",), suggest_values=False, example="session_id:123456"),
    _f("session_end_reason", "enum", "Why the session ended", "Session",
       expr="session_end_reason", example="session_end_reason:tcp-rst"),
    _f("duration", "duration", "Session duration in seconds", "Session",
       expr="toString(duration)", aliases=("elapsed_time",), suggest_values=False,
       example="duration:>300"),
    _f("sent_bytes", "bytes", "Bytes sent by the source", "Volume", expr="toString(sent_bytes)",
       aliases=("sentbyte", "bytes_sent"), suggest_values=False, example="sent_bytes:>1000000"),
    _f("recv_bytes", "bytes", "Bytes received by the source", "Volume", expr="toString(recv_bytes)",
       aliases=("rcvdbyte", "bytes_recv"), suggest_values=False, example="recv_bytes:>1000000"),
    _f("sentpkt", "number", "Packets sent", "Volume", expr="parsed_data['sentpkt']",
       suggest_values=False),
    _f("rcvdpkt", "number", "Packets received", "Volume", expr="parsed_data['rcvdpkt']",
       suggest_values=False),
    _f("trandisp", "string", "NAT translation disposition", "Session", expr="parsed_data['trandisp']"),

    # ── Device / classification ──────────────────────────────
    _f("device", "string", "Reporting device (IP or IP_VDOM)", "Device", expr=_DEVICE_EXPR,
       example="device:10.12.50.1"),
    _f("device_ip", "ip", "Reporting device IP", "Device", expr="toString(device_ip)",
       example="device_ip:10.12.50.1"),
    _f("devname", "string", "Reporting device hostname", "Device", expr="parsed_data['devname']",
       aliases=("device_name",)),
    _f("vdom", "string", "Virtual domain / vsys", "Device", expr="vdom",
       aliases=("vd", "vsys"), example="vdom:root"),
    _f("serial", "string", "Device serial number", "Device", expr="parsed_data['serial']"),
    # No static value list: vendors emit their own vocabulary here
    # (traffic/forward, TRAFFIC, utm/dns, …) so live values are the truth.
    _f("log_type", "enum", "Log type", "Classification", expr="log_type",
       aliases=("type",), example="log_type:~traffic"),
    _f("subtype", "string", "Log subtype", "Classification", expr="parsed_data['subtype']",
       example="subtype:forward"),
    _f("severity", "number", "Syslog severity (0=Emergency … 7=Debug)", "Classification",
       expr="toString(severity)", values=("0", "1", "2", "3", "4", "5", "6", "7"),
       example="severity:<4"),
    _f("level", "enum", "Vendor log level", "Classification", expr="parsed_data['level']",
       values=("emergency", "alert", "critical", "error", "warning", "notice",
               "information", "debug")),
    _f("facility", "number", "Syslog facility", "Classification", expr="toString(facility)",
       suggest_values=False),
    _f("logid", "string", "Vendor log ID", "Classification", expr="parsed_data['logid']"),

    # ── Content / time ───────────────────────────────────────
    _f("message", "text", "Parsed log message", "Content", expr="message",
       suggest_values=False, example="message:~timeout"),
    _f("raw", "text", "Raw syslog line", "Content", expr="raw", suggest_values=False),
    _f("msg", "text", "Vendor message field", "Content", expr="parsed_data['msg']",
       suggest_values=False),
    _f("timestamp", "datetime", "Event time", "Time", expr="toString(timestamp)",
       suggest_values=False),
]

CURATED_BY_NAME: Dict[str, NQLField] = {}
for _fld in CURATED_FIELDS:
    CURATED_BY_NAME[_fld.name] = _fld
    for _alias in _fld.aliases:
        CURATED_BY_NAME.setdefault(_alias, _fld)


# Values shown for well-known ports even before any live data comes back.
WELL_KNOWN_PORTS = {
    "20": "FTP data", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "67": "DHCP", "80": "HTTP", "110": "POP3", "123": "NTP",
    "135": "MS RPC", "139": "NetBIOS", "143": "IMAP", "161": "SNMP",
    "389": "LDAP", "443": "HTTPS", "445": "SMB", "465": "SMTPS", "514": "Syslog",
    "587": "SMTP submission", "636": "LDAPS", "993": "IMAPS", "995": "POP3S",
    "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL", "3389": "RDP",
    "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis", "8080": "HTTP alt",
    "8443": "HTTPS alt", "9200": "Elasticsearch",
}

PROTO_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6"}

SEVERITY_NAMES = {
    "0": "Emergency", "1": "Alert", "2": "Critical", "3": "Error",
    "4": "Warning", "5": "Notice", "6": "Informational", "7": "Debug",
}

OPERATORS = [
    (":", "equals", "action:deny"),
    (":!=", "not equals", "action:!=allow"),
    (":~", "contains (wildcards ok)", "policyname:~guest"),
    (":>", "greater than", "dstport:>1024"),
    (":>=", "greater or equal", "sent_bytes:>=1000000"),
    (":<", "less than", "severity:<4"),
    (":<=", "less or equal", "duration:<=60"),
]

KEYWORDS = [
    ("AND", "both conditions must match", "srcip:10.0.0.1 AND action:deny"),
    ("OR", "either condition matches", "action:deny OR action:drop"),
    ("NOT", "exclude what follows", "NOT dst_country:Ireland"),
    ("|", "start a pipeline stage", "| stats count by srcip"),
]

PIPELINE_COMMANDS = [
    ("stats", "aggregate results", "stats count by srcip"),
    ("where", "filter aggregated rows", "where count > 100"),
    ("sort", "order results (- for descending)", "sort -count"),
    ("limit", "cap the row count", "limit 20"),
]

STATS_FUNCS = [
    ("count", "number of matching events", "stats count by srcip"),
    ("sum", "total of a numeric field", "stats sum(sent_bytes) by srcip"),
    ("avg", "average of a numeric field", "stats avg(duration) by application"),
    ("min", "smallest value", "stats min(duration) by application"),
    ("max", "largest value", "stats max(sent_bytes) by srcip"),
    ("uniq", "approximate distinct count", "stats uniq(dstip) by srcip"),
    ("uniqExact", "exact distinct count", "stats uniqExact(dstip) by srcip"),
]


# ============================================================
# Dynamic field discovery (parsed_data keys)
# ============================================================

_dynamic_cache: Dict[str, Any] = {"keys": [], "ts": 0.0}
_dynamic_lock = threading.Lock()
_dynamic_refreshing = threading.Event()
DYNAMIC_TTL = 900          # 15 minutes


def discover_dynamic_keys(force: bool = False) -> List[str]:
    """Every key seen in `parsed_data` recently, most common first.

    Never blocks the caller: a stale or empty cache triggers a background refresh
    and the current list is returned immediately. Suggestions therefore always
    answer at once — the curated catalog is available from the first keystroke and
    discovered keys join it as soon as the refresh lands."""
    now = time.time()
    fresh = _dynamic_cache["keys"] and now - _dynamic_cache["ts"] < DYNAMIC_TTL
    if force:
        _refresh_dynamic_keys()
    elif not fresh and not _dynamic_refreshing.is_set():
        _dynamic_refreshing.set()
        threading.Thread(target=_refresh_dynamic_keys, name="nql-field-discovery",
                         daemon=True).start()
    return _dynamic_cache["keys"]


def _refresh_dynamic_keys() -> List[str]:
    """Re-read the parsed_data key list from ClickHouse into the cache."""
    with _dynamic_lock:
        keys: List[str] = []
        try:
            from ..db.clickhouse import ClickHouseClient
            client = ClickHouseClient.get_client()
            # A short recent window is enough to see every key every active
            # parser emits, and keeps the scan cheap. If ingestion has been quiet
            # widen the window rather than come back empty. `break` overflow modes
            # return partial results instead of throwing on a busy cluster.
            for window in ("30 MINUTE", "6 HOUR", "2 DAY"):
                rows = client.query(
                    f"SELECT k FROM ("
                    f"  SELECT arrayJoin(mapKeys(parsed_data)) AS k, count() AS c"
                    f"  FROM syslogs"
                    f"  PREWHERE timestamp > now() - INTERVAL {window}"
                    f"  GROUP BY k ORDER BY c DESC LIMIT 400"
                    f") SETTINGS max_execution_time = 8, timeout_overflow_mode = 'break',"
                    f"          max_rows_to_read = 50000000, read_overflow_mode = 'break'"
                ).result_rows
                keys = [str(r[0]) for r in rows if IDENT_RE.match(str(r[0]))]
                if len(keys) >= 20:
                    break
        except Exception as e:
            logger.warning(f"NQL dynamic field discovery failed: {e}")
            keys = _dynamic_cache["keys"]        # keep whatever we had
        finally:
            _dynamic_refreshing.clear()
        if keys:
            _dynamic_cache["keys"] = keys
            _dynamic_cache["ts"] = time.time()
            logger.info(f"NQL field discovery: {len(keys)} parsed_data keys cached")
        return keys


def warm_field_cache() -> None:
    """Populate the discovery cache off the request path (called at startup)."""
    try:
        _refresh_dynamic_keys()
    except Exception as e:
        logger.warning(f"NQL field cache warm-up failed: {e}")


def all_field_names() -> List[str]:
    """Curated names + aliases + discovered parsed_data keys."""
    names = list(CURATED_BY_NAME.keys())
    seen = set(names)
    for k in discover_dynamic_keys():
        if k not in seen:
            seen.add(k)
            names.append(k)
    return names


def resolve_field(name: str) -> Optional[NQLField]:
    """Curated field for `name`, or a synthesised one for a discovered
    parsed_data key. None if the name is not a legal identifier."""
    if not name or not IDENT_RE.match(name):
        return None
    fld = CURATED_BY_NAME.get(name.lower())
    if fld:
        return fld
    lower = name.lower()
    if lower in discover_dynamic_keys():
        return NQLField(
            name=lower, type="string", description="Parsed log field",
            category="Parsed", expr=f"parsed_data['{lower}']",
        )
    return None


def field_sql_expr(name: str) -> Optional[str]:
    """SQL expression that yields the field's value as a String, or None if the
    field name is not a legal identifier."""
    fld = resolve_field(name)
    if fld:
        return fld.value_expr()
    if IDENT_RE.match(name or ""):
        # Unknown but syntactically safe — treat as a parsed_data key so brand-new
        # parser output is searchable before the discovery cache refreshes.
        return f"parsed_data['{name.lower()}']"
    return None


# ============================================================
# Live value suggestions
# ============================================================

_value_cache: Dict[Tuple[str, str, int], Tuple[float, List[Dict[str, Any]]]] = {}
_value_lock = threading.Lock()
VALUE_TTL = 60
VALUE_SCAN_CAP = 400_000     # rows sampled per suggestion query (native column)
MAP_SCAN_CAP = 120_000       # ...and for a parsed_data Map lookup


def suggest_values(field_name: str, prefix: str = "", minutes: int = 60,
                   limit: int = 12) -> List[Dict[str, Any]]:
    """Top values for `field_name` (optionally starting with `prefix`) over the
    last `minutes`, with event counts. Bounded so the dropdown stays snappy."""
    fld = resolve_field(field_name)
    expr = field_sql_expr(field_name)
    if not expr or (fld and not fld.suggest_values):
        return []

    key = (field_name.lower(), prefix.lower(), minutes)
    now = time.time()
    cached = _value_cache.get(key)
    if cached and now - cached[0] < VALUE_TTL:
        return cached[1]

    safe_prefix = prefix.replace("\\", "\\\\").replace("'", "''")
    prefix_clause = ""
    if safe_prefix:
        prefix_clause = f" AND positionCaseInsensitive(v, '{safe_prefix}') = 1"
    # Ports/protocol/session default to 0 when the log had none — never a value
    # anyone wants to search for.
    if fld and fld.name in ("srcport", "dstport", "proto", "session_id"):
        prefix_clause += " AND v != '0'"

    # Map lookups cost several times what a native column does, so they get a
    # tighter sample — the dropdown wants a fast answer, not an exact ranking.
    scan_cap = MAP_SCAN_CAP if "parsed_data[" in expr else VALUE_SCAN_CAP

    sql = f"""
        SELECT v, count() AS c FROM (
            SELECT {expr} AS v
            FROM syslogs
            PREWHERE timestamp > now() - INTERVAL {int(minutes)} MINUTE
            WHERE v != ''{prefix_clause}
            LIMIT {scan_cap}
        )
        GROUP BY v ORDER BY c DESC LIMIT {int(limit)}
        SETTINGS max_execution_time = 5, max_rows_to_read = 200000000,
                 read_overflow_mode = 'break', timeout_overflow_mode = 'break'
    """
    try:
        from ..db.clickhouse import ClickHouseClient
        rows = ClickHouseClient.get_client().query(sql).result_rows
        out = [{"value": str(v), "count": int(c)} for v, c in rows]
    except Exception as e:
        logger.warning(f"NQL value suggestion for '{field_name}' failed: {e}")
        out = []

    with _value_lock:
        _value_cache[key] = (now, out)
        if len(_value_cache) > 500:                      # cheap bound
            oldest = sorted(_value_cache.items(), key=lambda kv: kv[1][0])[:200]
            for k, _ in oldest:
                _value_cache.pop(k, None)
    return out


def _static_value_hints(fld: Optional[NQLField], field_name: str,
                        prefix: str) -> List[Dict[str, Any]]:
    """Type-aware suggestions that need no query: enum members, well-known ports,
    protocol numbers, severity levels."""
    hints: List[Dict[str, Any]] = []
    p = prefix.lower()

    if field_name in ("dstport", "srcport", "dst_port", "src_port"):
        for port, name in WELL_KNOWN_PORTS.items():
            if port.startswith(p):
                hints.append({"value": port, "detail": name})
    elif field_name in ("proto", "protocol"):
        for num, name in PROTO_NAMES.items():
            if num.startswith(p) or name.lower().startswith(p):
                hints.append({"value": num, "detail": name})
    elif field_name == "severity":
        for num, name in SEVERITY_NAMES.items():
            if num.startswith(p) or name.lower().startswith(p):
                hints.append({"value": num, "detail": name})
    elif fld and fld.values:
        for v in fld.values:
            if v.lower().startswith(p):
                hints.append({"value": v, "detail": ""})
    return hints


# ============================================================
# Cursor-context analysis
# ============================================================

def _current_token(segment: str) -> Tuple[int, str]:
    """Start offset (within `segment`) and text of the token the cursor sits in.
    Quoted runs count as part of a single token so `policyname:"Allow We` works."""
    in_quotes = False
    start = 0
    for i, ch in enumerate(segment):
        if ch == '"':
            in_quotes = not in_quotes
        elif not in_quotes and ch in ' \t()':
            start = i + 1
    return start, segment[start:]


def _split_pipeline(text: str) -> List[Tuple[int, str]]:
    """Split on pipeline pipes (a `|` preceded by whitespace or at the start),
    leaving value-OR pipes (`action:deny|drop`) alone. Returns (offset, text)."""
    segments: List[Tuple[int, str]] = []
    in_quotes = False
    seg_start = 0
    for i, ch in enumerate(text):
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == '|' and not in_quotes:
            prev = text[i - 1] if i > 0 else ' '
            if i == 0 or prev in ' \t':
                segments.append((seg_start, text[seg_start:i]))
                seg_start = i + 1
    segments.append((seg_start, text[seg_start:]))
    return segments


def _quote_if_needed(value: str) -> str:
    if value and re.search(r'[\s()"]', value):
        return '"' + value.replace('"', '\\"') + '"'
    return value


def _fmt_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _field_suggestions(prefix: str, insert_suffix: str = ":") -> List[Dict[str, Any]]:
    """Fields matching `prefix`. Prefix matches rank above substring matches, and
    curated fields rank above discovered parsed_data keys."""
    p = (prefix or "").lower()
    starts: List[Dict[str, Any]] = []
    contains: List[Dict[str, Any]] = []
    seen: set = set()

    def add(name: str, fld: Optional[NQLField]):
        if name in seen:
            return
        low = name.lower()
        if p and p not in low:
            return
        seen.add(name)
        item = {
            "insert": name + insert_suffix,
            "label": name,
            "detail": (fld.description if fld else "Parsed log field"),
            "meta": (fld.type if fld else "string"),
            "group": "Fields",
            "example": (fld.example if fld else ""),
        }
        if fld and fld.name != name:
            item["detail"] = f"{fld.description} (alias of {fld.name})"
        (starts if low.startswith(p) else contains).append(item)

    for fld in CURATED_FIELDS:
        add(fld.name, fld)
    for alias, fld in CURATED_BY_NAME.items():
        add(alias, fld)
    for key in discover_dynamic_keys():
        add(key, None)

    return (starts + contains)[:40]


def _keyword_suggestions(prefix: str) -> List[Dict[str, Any]]:
    p = (prefix or "").lower()
    out = []
    for kw, desc, example in KEYWORDS:
        if not p or kw.lower().startswith(p):
            out.append({"insert": kw + " ", "label": kw, "detail": desc,
                        "meta": "keyword", "group": "Operators", "example": example})
    return out


def _operator_suggestions(field_name: str, fld: Optional[NQLField]) -> List[Dict[str, Any]]:
    """Comparison operators for `field:`. The insert text is the operator alone —
    replacement starts immediately after the colon the user already typed."""
    numeric = bool(fld and fld.type in ("number", "port", "bytes", "duration"))
    out = []
    for op, desc, example in OPERATORS:
        suffix = op[1:]                       # ":>=" -> ">="
        if not suffix:                        # plain equality needs no operator
            continue
        if suffix in (">", ">=", "<", "<=") and not numeric:
            continue
        out.append({"insert": suffix, "label": field_name + op,
                    "detail": desc, "meta": "operator", "group": "Operators",
                    "example": example})
    return out


def build_suggestions(query: str, cursor: Optional[int] = None,
                      minutes: int = 60) -> Dict[str, Any]:
    """Work out what the user is typing and return the matching completions.

    Returns {context, token, replace_start, replace_end, suggestions[]} where
    replace_start/replace_end are offsets into `query` that the chosen
    suggestion's `insert` text should replace.
    """
    query = query or ""
    if cursor is None or cursor < 0 or cursor > len(query):
        cursor = len(query)
    before = query[:cursor]

    segments = _split_pipeline(before)
    seg_offset, segment = segments[-1]
    in_pipeline = len(segments) > 1

    tok_start, token = _current_token(segment)
    abs_start = seg_offset + tok_start

    if in_pipeline:
        return _pipeline_suggestions(segment, seg_offset, tok_start, token, cursor)

    # ── Filter expression ────────────────────────────────────
    # Strip a leading negation so `-src` and `src` complete the same way.
    neg = ""
    body = token
    if body.startswith('-'):
        neg, body = "-", body[1:]
        abs_start += 1

    if ':' in body:
        field_name, rest = body.split(':', 1)
        fld = resolve_field(field_name)

        # Operator prefix on the value side (`dstport:>=`).
        op_match = re.match(r'^(!=|>=|<=|>|<|=|~)', rest)
        operator = op_match.group(1) if op_match else ""
        value_part = rest[len(operator):]

        # For OR-lists / comma lists, complete only the fragment after the last
        # separator so `action:deny|dr` suggests values for `dr`.
        sep_pos = max(value_part.rfind('|'), value_part.rfind(','))
        frag_offset = sep_pos + 1
        fragment = value_part[frag_offset:]

        quoted = fragment.startswith('"')
        prefix = fragment[1:] if quoted else fragment

        value_start = abs_start + len(field_name) + 1 + len(operator) + frag_offset
        suggestions = _value_suggestions(field_name, fld, prefix, operator, minutes)
        return {
            "context": "value",
            "field": field_name,
            "token": fragment,
            "replace_start": value_start,
            "replace_end": cursor,
            "suggestions": suggestions,
        }

    # No colon yet: field names, plus boolean keywords when a term precedes us.
    fields = _field_suggestions(body)
    preceding = segment[:tok_start].strip()
    keywords = _keyword_suggestions(body) if preceding else []
    if body and keywords:
        # Typing "AN" after a complete term almost always means AND — rank the
        # keyword above fields that merely contain those letters.
        suggestions = keywords + fields
    else:
        suggestions = fields + keywords
    if not body:
        suggestions = suggestions[:25]
    return {
        "context": "field",
        "field": None,
        "token": neg + body,
        "replace_start": abs_start,
        "replace_end": cursor,
        "suggestions": suggestions,
    }


def _value_suggestions(field_name: str, fld: Optional[NQLField], prefix: str,
                       operator: str, minutes: int) -> List[Dict[str, Any]]:
    """Completions for the value side of `field:`."""
    out: List[Dict[str, Any]] = []
    seen: set = set()

    # Real values first — they carry event counts and reflect what this
    # deployment actually logs. Static hints then fill in anything absent from
    # the current window (well-known ports, enum members nobody hit lately).
    static = {h["value"]: h["detail"] for h in _static_value_hints(fld, field_name.lower(), prefix)}

    for row in suggest_values(field_name, prefix, minutes):
        v = row["value"]
        if v in seen:
            continue
        seen.add(v)
        detail = f"{_fmt_count(row['count'])} events"
        if static.get(v):
            detail = f"{static[v]} — {detail}"
        out.append({"insert": _quote_if_needed(v) + " ", "label": v,
                    "detail": detail, "meta": "value", "group": "Values",
                    "example": "", "count": row["count"]})

    for v, detail in static.items():
        if v in seen:
            continue
        seen.add(v)
        out.append({"insert": _quote_if_needed(v) + " ", "label": v,
                    "detail": detail, "meta": "value",
                    "group": "Known values", "example": ""})

    if fld and fld.type == "ip":
        for tmpl, desc in (("10.0.0.0/8", "CIDR range"),
                           ("192.168.1.*", "wildcard match"),
                           ("10.0.0.1-10.0.0.50", "IP range")):
            if not prefix or tmpl.startswith(prefix):
                out.append({"insert": tmpl + " ", "label": tmpl, "detail": desc,
                            "meta": "pattern", "group": "Patterns", "example": ""})

    # With the value still empty, also advertise the comparison operators this
    # field supports — that's the moment the choice is being made.
    if not prefix and not operator:
        out.extend(_operator_suggestions(field_name, fld))
    return out


def _pipeline_suggestions(segment: str, seg_offset: int, tok_start: int,
                          token: str, cursor: int) -> Dict[str, Any]:
    """Completions inside a `| stats … | sort … | limit …` stage."""
    abs_start = seg_offset + tok_start
    stripped = segment.lstrip()
    lead_ws = len(segment) - len(stripped)
    words = stripped.split()
    cmd = words[0].lower() if words else ""
    typing_cmd = len(words) <= 1 and tok_start <= lead_ws + len(cmd)

    def wrap(context: str, suggestions: List[Dict[str, Any]], start: int = abs_start):
        return {"context": context, "field": None, "token": token,
                "replace_start": start, "replace_end": cursor,
                "suggestions": suggestions}

    if typing_cmd:
        p = token.lower()
        return wrap("pipeline", [
            {"insert": name + " ", "label": name, "detail": desc,
             "meta": "command", "group": "Pipeline", "example": example}
            for name, desc, example in PIPELINE_COMMANDS if name.startswith(p)
        ])

    if cmd == "stats":
        # After `by`, complete group-by fields; before it, complete functions/`by`.
        if re.search(r'\bby\b[^|]*$', stripped, re.IGNORECASE):
            return wrap("pipeline_field", _field_suggestions(token, insert_suffix=""))
        p = token.lower()
        out = [{"insert": name + ("(" if name != "count" else " "), "label": name,
                "detail": desc, "meta": "function", "group": "Aggregations",
                "example": example}
               for name, desc, example in STATS_FUNCS if name.lower().startswith(p)]
        if not p or "by".startswith(p):
            out.append({"insert": "by ", "label": "by", "detail": "group results by a field",
                        "meta": "keyword", "group": "Aggregations",
                        "example": "stats count by srcip"})
        return wrap("pipeline", out)

    if cmd in ("sort", "where"):
        # `sort -count` / `sort +srcip`: the sign stays, completion applies to the
        # field name after it.
        start, name = abs_start, token
        if cmd == "sort" and name[:1] in ("-", "+"):
            start, name = start + 1, name[1:]
        fields = _field_suggestions(name, insert_suffix="")
        aggs = [{"insert": a + " ", "label": a, "detail": "aggregate result column",
                 "meta": "number", "group": "Aggregations", "example": ""}
                for a in ("count", "value") if a.startswith(name.lower())]
        extra = []
        if cmd == "sort" and not token:
            extra = [{"insert": "-count ", "label": "-count",
                      "detail": "descending by event count", "meta": "sort",
                      "group": "Pipeline", "example": "sort -count"}]
        return wrap("pipeline_field", extra + aggs + fields, start)

    if cmd == "limit":
        return wrap("pipeline", [
            {"insert": n + " ", "label": n, "detail": "rows to return",
             "meta": "number", "group": "Pipeline", "example": ""}
            for n in ("10", "20", "50", "100", "500") if n.startswith(token)
        ])

    return wrap("pipeline", [])


# ============================================================
# Catalog export (for the help panel / field reference)
# ============================================================

def field_catalog() -> Dict[str, Any]:
    """Grouped field reference for the UI's help panel."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for fld in CURATED_FIELDS:
        groups.setdefault(fld.category, []).append({
            "name": fld.name,
            "type": fld.type,
            "description": fld.description,
            "aliases": list(fld.aliases),
            "example": fld.example,
        })
    dynamic = [k for k in discover_dynamic_keys() if k not in CURATED_BY_NAME]
    return {
        "groups": groups,
        "dynamic": dynamic,
        "operators": [{"op": o, "description": d, "example": e} for o, d, e in OPERATORS],
        "keywords": [{"keyword": k, "description": d, "example": e} for k, d, e in KEYWORDS],
        "pipeline": [{"command": c, "description": d, "example": e} for c, d, e in PIPELINE_COMMANDS],
    }
