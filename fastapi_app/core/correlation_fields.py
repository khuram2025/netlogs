"""
Correlation source field catalog.

Phase 0 hardening: a central allow-list of the columns each correlation data
source exposes, so the correlation engine can validate filter/group-by fields
before they reach a ClickHouse query and bind values as parameters instead of
interpolating them into SQL.

This is intentionally a small, data-only module (no imports from services or
schemas) so it can be shared by both ``services/correlation_engine.py`` and
``schemas/correlation.py`` without creating an import cycle. Phase 4 will grow
this into a full source registry.

Field types:
    "string"  -> equality / inequality only, bound as a String parameter
    "numeric" -> supports >, <, >=, <=, =, != ; bound as a Float64 parameter
    "ip"      -> equality / inequality, bound as String and wrapped in toIPv4()
"""

# Maps a logical data source -> the ClickHouse table it reads from.
SOURCE_TABLES = {
    "syslogs": "syslogs",
}

# Default source when a stage does not declare one (back-compat with v1 rules).
DEFAULT_SOURCE = "syslogs"

# Per-source allow-list of filterable / groupable columns and their value type.
# Derived from `DESCRIBE TABLE syslogs`.
SOURCE_FIELDS = {
    "syslogs": {
        "device_ip": "ip",
        "facility": "numeric",
        "severity": "numeric",
        "message": "string",
        "srcip": "string",
        "dstip": "string",
        "srcport": "numeric",
        "dstport": "numeric",
        "proto": "numeric",
        "action": "string",
        "policyname": "string",
        "log_type": "string",
        "application": "string",
        "src_zone": "string",
        "dst_zone": "string",
        "session_end_reason": "string",
        "threat_id": "string",
        "vdom": "string",
        "log_hour": "numeric",
    },
}

# Suffix -> SQL comparison operator. Ordered longest-suffix-first so that, e.g.,
# "dstport_gte" is matched as "_gte" and never mis-split as "_gt"/"_te".
COMPARISON_SUFFIXES = (
    ("_gte", ">="),
    ("_lte", "<="),
    ("_gt", ">"),
    ("_lt", "<"),
    ("_ne", "!="),
)

# Operators that only make sense on a numeric field.
NUMERIC_ONLY_OPERATORS = {">", "<", ">=", "<="}

# Keys that appear inside a stage "filter" dict but are not field conditions.
NON_FIELD_FILTER_KEYS = {"group_by", "threshold", "window"}


def parse_field_op(key: str):
    """Split a filter key into (field_name, sql_operator).

    "dstport_gt" -> ("dstport", ">"); a plain "action" -> ("action", "=").
    """
    for suffix, op in COMPARISON_SUFFIXES:
        if key.endswith(suffix) and len(key) > len(suffix):
            return key[: -len(suffix)], op
    return key, "="


def get_source_fields(source: str) -> dict:
    """Return the field catalog for a source, or None if the source is unknown."""
    return SOURCE_FIELDS.get(source)


def is_valid_source(source: str) -> bool:
    return source in SOURCE_FIELDS
