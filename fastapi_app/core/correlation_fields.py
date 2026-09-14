"""
Correlation source registry & canonical entity model.

Phase 4: grows the Phase-0 single-source field allow-list into a multi-source
registry. Each source declares its ClickHouse table, the columns that may be
filtered/grouped (with value types), and a mapping from **canonical entities**
to that source's native columns — so a rule can correlate, say, a DNS lookup
with a firewall connection because both expose the canonical ``ip`` entity.

Data-only module (no imports from services/schemas) so it can be shared
without an import cycle.

Field value types:
    "string"  -> equality / inequality, bound as a String parameter
    "numeric" -> supports >, <, >=, <=, =, != ; bound as Float64
    "ip"      -> equality / inequality, bound as String, wrapped in toIPv4()

Canonical entities link stages across sources: a rule joins on ``ip`` /
``user`` / ``host`` / ``domain`` / ``url`` / ``device`` and each source
resolves that to its own column.
"""

# Canonical cross-source entity types.
CANONICAL_ENTITIES = ["ip", "dst_ip", "user", "host", "domain", "url", "device"]

# Default source when a stage does not declare one (back-compat with v1 rules).
DEFAULT_SOURCE = "syslogs"


# ── The registry ────────────────────────────────────────────────────────
# Each source: table, human label, filterable fields {name: type}, and
# entities {canonical_entity: native_column}.
SOURCES = {
    "syslogs": {
        "table": "syslogs",
        "label": "Firewall Traffic",
        "fields": {
            "device_ip": "ip", "facility": "numeric", "severity": "numeric",
            "message": "string", "srcip": "string", "dstip": "string",
            "srcport": "numeric", "dstport": "numeric", "proto": "numeric",
            "action": "string", "policyname": "string", "log_type": "string",
            "application": "string", "src_zone": "string", "dst_zone": "string",
            "session_end_reason": "string", "threat_id": "string",
            "vdom": "string", "log_hour": "numeric",
        },
        "entities": {"ip": "srcip", "dst_ip": "dstip", "device": "device_ip"},
        "sample_columns": ["timestamp", "srcip", "dstip", "dstport", "action", "policyname"],
    },
    "dns_logs": {
        "table": "dns_logs",
        "label": "DNS Queries",
        "fields": {
            "device_ip": "string", "action": "string", "src_ip": "string",
            "dest_ip": "string", "src_port": "numeric", "dest_port": "numeric",
            "transport": "string", "src_user": "string", "qname": "string",
            "qtype": "string", "resolved_ip": "string", "category": "string",
            "severity": "string", "direction": "string", "policy": "string",
            "src_zone": "string", "dest_zone": "string", "src_country": "string",
            "dest_country": "string", "event_type": "string",
            "threat_name": "string", "threat_id": "string",
        },
        "entities": {"ip": "src_ip", "dst_ip": "dest_ip", "user": "src_user",
                     "domain": "qname", "device": "device_ip"},
        "sample_columns": ["timestamp", "src_ip", "dest_ip", "qname", "action", "category"],
    },
    "url_logs": {
        "table": "url_logs",
        "label": "URL / Web Access",
        "fields": {
            "device_ip": "string", "action": "string", "src_ip": "string",
            "dest_ip": "string", "src_port": "numeric", "dest_port": "numeric",
            "transport": "string", "src_user": "string", "url": "string",
            "hostname": "string", "url_category": "string",
            "http_method": "string", "user_agent": "string",
            "content_type": "string", "direction": "string",
            "severity": "string", "policy": "string", "application": "string",
            "service": "string", "src_zone": "string", "dest_zone": "string",
            "src_country": "string", "dest_country": "string",
            "sent_bytes": "numeric", "recv_bytes": "numeric",
            "event_type": "string", "request_type": "string",
        },
        "entities": {"ip": "src_ip", "dst_ip": "dest_ip", "user": "src_user",
                     "url": "url", "host": "hostname", "device": "device_ip"},
        "sample_columns": ["timestamp", "src_ip", "dest_ip", "url", "action", "url_category"],
    },
    "ioc_matches": {
        "table": "ioc_matches",
        "label": "Threat-Intel IOC Hits",
        "fields": {
            "ioc_type": "string", "ioc_value": "string", "threat_type": "string",
            "severity": "string", "confidence": "numeric",
            "matched_field": "string", "device_ip": "ip", "srcip": "string",
            "dstip": "string", "srcport": "numeric", "dstport": "numeric",
            "action": "string", "feed_name": "string",
        },
        "entities": {"ip": "srcip", "dst_ip": "dstip", "device": "device_ip"},
        "sample_columns": ["timestamp", "srcip", "dstip", "ioc_value", "threat_type", "feed_name"],
    },
    "audit_logs": {
        "table": "audit_logs",
        "label": "Platform Audit Log",
        "fields": {
            "user_id": "numeric", "username": "string", "action": "string",
            "resource_type": "string", "resource_id": "string",
            "resource_name": "string", "ip_address": "string",
        },
        "entities": {"ip": "ip_address", "user": "username"},
        "sample_columns": ["timestamp", "username", "action", "resource_type",
                           "resource_name", "ip_address"],
    },
    "pa_threat_logs": {
        "table": "pa_threat_logs",
        "label": "Palo Alto Threat Logs",
        "fields": {
            "device_ip": "string", "log_subtype": "string", "severity": "string",
            "direction": "string", "action": "string", "src_ip": "string",
            "dest_ip": "string", "src_port": "numeric", "dest_port": "numeric",
            "transport": "string", "src_zone": "string", "dest_zone": "string",
            "src_user": "string", "dest_user": "string", "application": "string",
            "rule": "string", "threat_id": "string", "threat_name": "string",
            "threat_category": "string", "category": "string", "url": "string",
            "http_method": "string", "file_name": "string", "file_hash": "string",
            "file_type": "string", "src_hostname": "string",
            "dest_hostname": "string", "risk_of_app": "numeric",
        },
        "entities": {"ip": "src_ip", "dst_ip": "dest_ip", "user": "src_user",
                     "host": "src_hostname", "url": "url", "device": "device_ip"},
        "sample_columns": ["timestamp", "src_ip", "dest_ip", "threat_name",
                           "severity", "action"],
    },
    "correlation_matches": {
        "table": "correlation_matches",
        "label": "Correlation Matches (meta)",
        "fields": {
            "rule_id": "numeric", "rule_name": "string", "severity": "string",
            "entity_type": "string", "entity_value": "string",
            "match_fingerprint": "string", "total_events": "numeric",
            "mitre_tactic": "string", "mitre_technique": "string",
            "status": "string",
        },
        # A correlation match's entity is its entity_value column.
        "entities": {"ip": "entity_value"},
        "sample_columns": ["timestamp", "rule_name", "entity_value",
                           "severity", "status"],
    },
}

# Suffix -> SQL comparison operator. Ordered longest-suffix-first.
COMPARISON_SUFFIXES = (
    ("_gte", ">="),
    ("_lte", "<="),
    ("_gt", ">"),
    ("_lt", "<"),
    ("_ne", "!="),
)

NUMERIC_ONLY_OPERATORS = {">", "<", ">=", "<="}
NON_FIELD_FILTER_KEYS = {"group_by", "threshold", "window"}


# ── Back-compat derived views (Phase 0–3 imported these names) ───────────
SOURCE_FIELDS = {name: src["fields"] for name, src in SOURCES.items()}
SOURCE_TABLES = {name: src["table"] for name, src in SOURCES.items()}


def parse_field_op(key: str):
    """Split a filter key into (field_name, sql_operator).

    "dstport_gt" -> ("dstport", ">"); a plain "action" -> ("action", "=").
    """
    for suffix, op in COMPARISON_SUFFIXES:
        if key.endswith(suffix) and len(key) > len(suffix):
            return key[: -len(suffix)], op
    return key, "="


def get_source(name: str) -> dict:
    """Return the full source definition, or None if unknown."""
    return SOURCES.get(name)


def get_source_fields(source: str) -> dict:
    """Return {field: type} for a source, or None if the source is unknown."""
    src = SOURCES.get(source)
    return src["fields"] if src else None


def get_source_entities(source: str) -> dict:
    """Return {canonical_entity: native_column} for a source ({} if unknown)."""
    src = SOURCES.get(source)
    return src["entities"] if src else {}


def get_sample_columns(source: str) -> list:
    """Columns to pull as sample evidence for a source."""
    src = SOURCES.get(source)
    return src["sample_columns"] if src else ["timestamp"]


def is_valid_source(source: str) -> bool:
    return source in SOURCES


def resolve_field(source: str, key: str):
    """Resolve a join key — a canonical entity *or* a native column — to the
    source's native column name. Returns None if it resolves to nothing."""
    src = SOURCES.get(source)
    if not src:
        return None
    if key in src["entities"]:
        return src["entities"][key]
    if key in src["fields"]:
        return key
    return None
