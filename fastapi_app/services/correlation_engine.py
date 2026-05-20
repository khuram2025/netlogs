"""
Correlation Engine - Multi-stage event correlation for detecting complex attack patterns.

Evaluates correlation rules by querying ClickHouse for events matching each stage
in sequence, with variable substitution between stages.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.correlation import CorrelationRule
from ..models.alert import Alert, AlertRule
from ..core.correlation_fields import (
    DEFAULT_SOURCE,
    NON_FIELD_FILTER_KEYS,
    NUMERIC_ONLY_OPERATORS,
    SOURCE_TABLES,
    get_source_fields,
    parse_field_op,
)

logger = logging.getLogger(__name__)

# Duplicate-alert / match dedup window.
ALERT_DEDUP_MINUTES = 5


class StageEvalError(Exception):
    """Raised when a correlation stage cannot be evaluated safely.

    Covers an invalid filter field, an operator/type mismatch, a non-numeric
    value for a numeric field, or a required ``$stageN.field`` variable that
    could not be resolved. The engine treats any of these as a *stage failure*
    (fail-closed) rather than silently broadening or skipping the condition.
    """


def _recent_alert_cutoff(minutes: int = ALERT_DEDUP_MINUTES) -> datetime:
    """Return the UTC timestamp ``minutes`` ago.

    Replaces the old ``datetime.replace(minute=now.minute - 5)`` which raised
    ``ValueError`` during the first five minutes of every hour.
    """
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


# Maps a stage group-by field to a canonical entity type (Phase 1: IP-centric;
# Phase 4 grows this into a full entity model).
_ENTITY_TYPE_BY_FIELD = {
    "srcip": "ip",
    "dstip": "ip",
    "device_ip": "ip",
}


def _entity_type_for_field(field: Optional[str]) -> str:
    """Canonical entity type for a group-by field."""
    if not field:
        return "none"
    return _ENTITY_TYPE_BY_FIELD.get(field, field)


def match_fingerprint(rule_id: int, rule_version: int,
                      entity_type: str, entity_value: str) -> str:
    """Stable identifier for a (rule, rule-version, entity) attack chain.

    Two matches with the same fingerprint are 'the same chain'. Suppression
    keeps a discrete rule from recording the same fingerprint more than once
    per suppression window — so match counts measure distinct chains, not
    scheduler ticks.
    """
    raw = f"{rule_id}|{rule_version}|{entity_type}|{entity_value}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _is_match_suppressed(fingerprint: str, suppress_window: int) -> bool:
    """True if a match with this fingerprint was already recorded inside the
    suppression window — used to stop a discrete rule from re-recording the
    same attack chain on every 60-second scheduler tick."""
    if not fingerprint:
        return False
    try:
        client = ClickHouseClient.get_client()
        r = client.query(
            "SELECT count() FROM correlation_matches "
            "WHERE match_fingerprint = {fp:String} "
            "AND timestamp > now() - INTERVAL {w:UInt32} SECOND",
            parameters={"fp": fingerprint, "w": int(suppress_window)},
        )
        return bool(r.result_rows) and r.result_rows[0][0] > 0
    except Exception as e:
        # Fail open on the suppression check: recording a possible duplicate
        # is safer than silently dropping a genuine new match.
        logger.error(f"Suppression check failed: {e}")
        return False


def ensure_correlation_matches_table():
    """Create the correlation_matches table in ClickHouse if it doesn't exist."""
    try:
        client = ClickHouseClient.get_client()
        client.command("""
            CREATE TABLE IF NOT EXISTS correlation_matches (
                timestamp DateTime64(3),
                rule_id UInt32,
                rule_name String,
                severity String,
                stages_matched UInt8,
                total_stages UInt8,
                stage_details String,
                key_value String,
                total_events UInt32,
                mitre_tactic String,
                mitre_technique String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, rule_id)
            TTL toDateTime(timestamp) + INTERVAL 6 MONTH DELETE
        """)
        logger.info("Correlation matches table ensured in ClickHouse")
    except Exception as e:
        logger.error(f"Failed to create correlation_matches table: {e}")


def _resolve_variable(value: str, variables: dict):
    """Resolve a ``$stageN.field`` reference.

    Returns (resolved_value, optional_flag). ``optional_flag`` is True when the
    reference ended with ``?`` (an explicitly optional variable). Raises
    ``StageEvalError`` when a *required* variable cannot be resolved — the
    engine must fail closed rather than drop the join condition.
    """
    ref = value[1:]
    optional = ref.endswith("?")
    if optional:
        ref = ref[:-1]

    resolved = None
    parts = ref.split(".", 1)
    if len(parts) == 2 and variables:
        stage_key, var_field = parts
        resolved = (variables.get(stage_key) or {}).get(var_field)

    if resolved is None or resolved == "":
        if optional:
            return None, True
        raise StageEvalError(
            f"Required variable '{value}' could not be resolved from a prior stage"
        )
    return resolved, optional


def _build_where_clause(filter_config: dict, variables: dict = None,
                        source: str = DEFAULT_SOURCE) -> Tuple[str, dict]:
    """Build a parameterized ClickHouse WHERE clause from a stage filter config.

    Returns ``(where_sql, params)`` where ``where_sql`` contains only
    allow-listed identifiers and ``{pN:Type}`` placeholders, and ``params`` maps
    each placeholder to its bound value. Raises ``StageEvalError`` on an
    unknown field, an operator/type mismatch, a bad numeric value, or an
    unresolved required variable (fail-closed).
    """
    fields = get_source_fields(source)
    if fields is None:
        raise StageEvalError(f"Unknown data source '{source}'")

    conditions: List[str] = []
    params: dict = {}
    idx = 0

    for key, value in (filter_config or {}).items():
        if key in NON_FIELD_FILTER_KEYS:
            continue

        actual_field, op = parse_field_op(key)
        if actual_field not in fields:
            raise StageEvalError(
                f"Field '{actual_field}' is not an allowed column for source '{source}'"
            )
        ftype = fields[actual_field]

        # Variable substitution ($stage1.srcip -> actual value), fail-closed.
        if isinstance(value, str) and value.startswith("$"):
            resolved, optional = _resolve_variable(value, variables)
            if resolved is None and optional:
                continue  # explicitly optional + unresolved -> skip condition
            value = resolved

        if op in NUMERIC_ONLY_OPERATORS and ftype != "numeric":
            raise StageEvalError(
                f"Operator '{op}' on '{actual_field}' requires a numeric field"
            )

        pname = f"p{idx}"
        idx += 1

        if ftype == "numeric":
            try:
                params[pname] = float(value)
            except (TypeError, ValueError):
                raise StageEvalError(
                    f"Filter '{key}' requires a numeric value, got {value!r}"
                )
            conditions.append(f"{actual_field} {op} {{{pname}:Float64}}")
        elif ftype == "ip":
            params[pname] = str(value)
            conditions.append(f"{actual_field} {op} toIPv4({{{pname}:String}})")
        else:  # string
            params[pname] = str(value)
            conditions.append(f"{actual_field} {op} {{{pname}:String}}")

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


def _fetch_stage_samples(table: str, full_where: str, params: dict,
                         group_by: str = None, group_by_type: str = None,
                         key_value: str = None, limit: int = 3) -> list:
    """Best-effort: fetch a few representative raw events for a matched stage.

    These are stored with the match as an evidence trail so an analyst can see
    *why* a stage matched without re-querying approximate logs.
    """
    try:
        client = ClickHouseClient.get_client()
        where = full_where
        p = dict(params)
        # Narrow samples to the matched entity when the group-by field is a
        # string/ip column (covers srcip/dstip — every current rule).
        if group_by and key_value is not None and group_by_type in (None, "string", "ip"):
            if group_by_type == "ip":
                where += f" AND {group_by} = toIPv4({{skey:String}})"
            else:
                where += f" AND {group_by} = {{skey:String}}"
            p["skey"] = str(key_value)
        cols = "timestamp, srcip, dstip, dstport, action, policyname"
        query = (f"SELECT {cols} FROM {table} WHERE {where} "
                 f"ORDER BY timestamp DESC LIMIT {int(limit)}")
        rows = client.query(query, parameters=p).result_rows
        return [
            {"timestamp": str(r[0]), "srcip": str(r[1]), "dstip": str(r[2]),
             "dstport": r[3], "action": str(r[4]), "policyname": str(r[5])}
            for r in rows
        ]
    except Exception as e:
        logger.debug(f"Stage sample fetch failed: {e}")
        return []


def _evaluate_stage(
    stage: dict,
    window_seconds: int,
    variables: dict = None,
    reference_time: str = "now()",
) -> Tuple[bool, dict]:
    """
    Evaluate a single correlation stage against ClickHouse logs.
    Returns (matched: bool, stage_result: dict with key values, event count,
    event-time bounds and sample evidence).
    """
    try:
        client = ClickHouseClient.get_client()
        filter_config = stage.get("filter", {}) or {}
        source = stage.get("source", DEFAULT_SOURCE)
        table = SOURCE_TABLES.get(source)
        if table is None:
            raise StageEvalError(f"Unknown data source '{source}'")

        try:
            threshold = int(stage.get("threshold", 1))
        except (TypeError, ValueError):
            raise StageEvalError(f"Invalid threshold: {stage.get('threshold')!r}")
        try:
            window_seconds = int(window_seconds)
        except (TypeError, ValueError):
            raise StageEvalError(f"Invalid window: {window_seconds!r}")

        group_by = filter_config.get("group_by", stage.get("group_by"))
        if group_by is not None:
            allowed = get_source_fields(source) or {}
            if group_by not in allowed:
                raise StageEvalError(
                    f"group_by field '{group_by}' is not an allowed column for source '{source}'"
                )

        where, params = _build_where_clause(filter_config, variables, source)
        # reference_time and window_seconds are engine-controlled (constant or
        # int-cast); group_by is allow-list validated. Only user values below
        # are bound as parameters.
        time_filter = f"timestamp > {reference_time} - INTERVAL {window_seconds} SECOND"
        full_where = f"{time_filter} AND ({where})"

        if group_by:
            # Aggregation query: find groups exceeding threshold, capturing
            # the event-time span of each group as evidence.
            query = f"""
                SELECT {group_by}, count() as cnt,
                       min(timestamp) as first_ts, max(timestamp) as last_ts
                FROM {table}
                WHERE {full_where}
                GROUP BY {group_by}
                HAVING cnt >= {threshold}
                ORDER BY cnt DESC
                LIMIT 10
            """
            result = client.query(query, parameters=params)
            rows = result.result_rows

            if not rows:
                return False, {}

            # Return the top match
            top_key = str(rows[0][0])
            top_count = rows[0][1]
            first_ts, last_ts = rows[0][2], rows[0][3]
            gb_type = (get_source_fields(source) or {}).get(group_by)
            samples = _fetch_stage_samples(table, full_where, params,
                                           group_by, gb_type, top_key)

            return True, {
                "key": top_key,
                "count": top_count,
                group_by: top_key,
                "first_event": first_ts,
                "last_event": last_ts,
                "source": source,
                "samples": samples,
                "all_matches": [{"key": str(r[0]), "count": r[1]} for r in rows[:5]],
            }
        else:
            # Simple count query with event-time bounds.
            query = f"""
                SELECT count() as cnt,
                       min(timestamp) as first_ts, max(timestamp) as last_ts
                FROM {table}
                WHERE {full_where}
            """
            result = client.query(query, parameters=params)
            row = result.result_rows[0] if result.result_rows else (0, None, None)
            count = row[0]

            if count >= threshold:
                samples = _fetch_stage_samples(table, full_where, params)
                return True, {
                    "count": count,
                    "first_event": row[1],
                    "last_event": row[2],
                    "source": source,
                    "samples": samples,
                }
            return False, {"count": count}

    except StageEvalError as e:
        logger.warning(f"Stage '{stage.get('name', '?')}' not evaluated: {e}")
        return False, {"error": str(e)}
    except Exception as e:
        logger.error(f"Stage evaluation error: {e}")
        return False, {"error": str(e)}


def evaluate_correlation_rule(rule: CorrelationRule) -> Optional[dict]:
    """
    Evaluate a single correlation rule through all its stages.
    Returns match details if all stages match, None otherwise.
    """
    stages = rule.stages
    if not stages or not isinstance(stages, list):
        return None

    variables = {}
    stage_results = []
    total_events = 0
    event_times: List[datetime] = []

    for i, stage in enumerate(stages):
        stage_name = stage.get("name", f"Stage {i + 1}")
        window = stage.get("window", 300)

        matched, result = _evaluate_stage(stage, window, variables)

        stage_results.append({
            "name": stage_name,
            "matched": matched,
            "window": window,
            "filter": stage.get("filter", {}),
            "threshold": stage.get("threshold", 1),
            **result,
        })

        if not matched:
            return None  # Chain broken

        # Store variables for next stage
        stage_key = f"stage{i + 1}"
        variables[stage_key] = result
        total_events += result.get("count", 0)
        for ts in (result.get("first_event"), result.get("last_event")):
            if ts is not None:
                event_times.append(ts)

    # All stages matched — build the match record with entity identity,
    # a stable fingerprint and the event-time span of the evidence.
    entity_value = stage_results[0].get("key", "")
    first_stage_filter = stages[0].get("filter", {}) or {}
    group_by_field = first_stage_filter.get("group_by", stages[0].get("group_by"))
    entity_type = _entity_type_for_field(group_by_field)
    rule_version = getattr(rule, "version", 1) or 1
    fingerprint = match_fingerprint(rule.id, rule_version, entity_type, entity_value)

    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    first_seen = min(event_times) if event_times else now_naive
    last_seen = max(event_times) if event_times else now_naive

    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "rule_version": rule_version,
        "severity": rule.severity,
        "stages": stage_results,
        "total_events": total_events,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "key_value": entity_value,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "match_fingerprint": fingerprint,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def record_correlation_match(match: dict):
    """Record a correlation match in ClickHouse.

    ``timestamp`` is the engine evaluation time; ``first_seen`` / ``last_seen``
    are the event-chain time bounds drawn from the matched evidence.
    """
    try:
        client = ClickHouseClient.get_client()
        now = datetime.now(timezone.utc)
        n_stages = len(match["stages"])

        client.insert("correlation_matches",
            [[
                now,
                match["rule_id"],
                match["rule_name"],
                match["severity"],
                n_stages,
                n_stages,
                json.dumps(match["stages"], default=str),
                match.get("key_value", "") or "",
                match.get("total_events", 0),
                match.get("mitre_tactic", "") or "",
                match.get("mitre_technique", "") or "",
                match.get("rule_version", 1) or 1,
                match.get("match_fingerprint", "") or "",
                match.get("entity_type", "") or "",
                match.get("entity_value", "") or "",
                match.get("first_seen") or now,
                match.get("last_seen") or now,
                "open",
            ]],
            column_names=[
                "timestamp", "rule_id", "rule_name", "severity",
                "stages_matched", "total_stages", "stage_details",
                "key_value", "total_events", "mitre_tactic", "mitre_technique",
                "rule_version", "match_fingerprint", "entity_type",
                "entity_value", "first_seen", "last_seen", "status",
            ]
        )
    except Exception as e:
        logger.error(f"Failed to record correlation match: {e}")


async def create_correlation_alert(match: dict):
    """Create an alert from a correlation match.

    Deduplicates on the exact alert title — which carries both the rule name
    and the implicated entity — so a noisy entity and a genuinely new entity
    no longer suppress each other (the old check matched the rule name only).
    """
    try:
        entity = match.get("entity_value", match.get("key_value", "")) or ""
        title = f"Correlation: {match['rule_name']} [{entity}]"

        async with async_session_maker() as db:
            from sqlalchemy import and_, func
            recent = await db.execute(
                select(func.count(Alert.id)).where(
                    and_(
                        Alert.title == title,
                        Alert.triggered_at > _recent_alert_cutoff(),
                    )
                )
            )
            if recent.scalar() > 0:
                return  # this rule+entity already alerted recently

            stages_summary = " -> ".join(
                f"{s['name']} ({s.get('count', 0)} events)"
                for s in match["stages"]
            )

            alert = Alert(
                title=title,
                severity=match["severity"],
                status="new",
                details=json.dumps({
                    "correlation_rule": match["rule_name"],
                    "rule_version": match.get("rule_version", 1),
                    "match_fingerprint": match.get("match_fingerprint", ""),
                    "entity_type": match.get("entity_type", ""),
                    "entity_value": entity,
                    "stages": match["stages"],
                    "total_events": match["total_events"],
                    "key_value": match.get("key_value", ""),
                    "attack_chain": stages_summary,
                    "first_seen": match.get("first_seen"),
                    "last_seen": match.get("last_seen"),
                    "mitre_tactic": match.get("mitre_tactic", ""),
                    "mitre_technique": match.get("mitre_technique", ""),
                }, default=str),
                triggered_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            await db.commit()
            logger.info(f"Correlation alert created: {title}")
    except Exception as e:
        logger.error(f"Failed to create correlation alert: {e}")


async def evaluate_all_correlation_rules():
    """Evaluate all enabled correlation rules. Called by the scheduler."""
    try:
        async with async_session_maker() as db:
            result = await db.execute(
                select(CorrelationRule).where(CorrelationRule.is_enabled == True)
            )
            rules = result.scalars().all()

            if not rules:
                return

            matched_count = 0
            suppressed_count = 0
            for rule in rules:
                try:
                    match = evaluate_correlation_rule(rule)
                    if match:
                        mode = getattr(rule, "match_mode", "discrete") or "discrete"
                        window = getattr(rule, "suppress_window", 3600) or 3600

                        # Discrete rules record a given attack chain at most
                        # once per suppression window — so match counts measure
                        # distinct chains, not 60-second scheduler ticks.
                        # Recurring rules are intentional monitors: always record.
                        if mode == "discrete" and _is_match_suppressed(
                                match["match_fingerprint"], window):
                            suppressed_count += 1
                        else:
                            matched_count += 1
                            record_correlation_match(match)
                            await create_correlation_alert(match)
                            rule.last_triggered_at = datetime.now(timezone.utc)
                            rule.trigger_count = (rule.trigger_count or 0) + 1

                    rule.last_evaluated_at = datetime.now(timezone.utc)
                except Exception as e:
                    logger.error(f"Error evaluating correlation rule '{rule.name}': {e}")

            await db.commit()

            if matched_count or suppressed_count:
                logger.info(
                    f"Correlation engine: {matched_count} recorded, "
                    f"{suppressed_count} suppressed (already recorded in window), "
                    f"of {len(rules)} rules"
                )

    except Exception as e:
        logger.error(f"Correlation engine error: {e}")


async def seed_correlation_rules():
    """Seed pre-built correlation rules."""
    async with async_session_maker() as db:
        # Check existing rules
        result = await db.execute(select(CorrelationRule.name))
        existing = {r[0] for r in result.all()}

        rules = [
            {
                "name": "Reconnaissance then Access",
                "description": "Port scan (>10 denied ports) followed by allowed connection from same IP within 10 minutes.",
                "severity": "high",
                "stages": [
                    {
                        "name": "Port Scan Detected",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 10,
                        "window": 300,
                    },
                    {
                        "name": "Successful Access",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 600,
                    },
                ],
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
            },
            {
                "name": "Brute Force then Login",
                "description": "Multiple denied connections followed by allowed connection from same source IP.",
                "severity": "critical",
                "stages": [
                    {
                        "name": "Multiple Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 20,
                        "window": 300,
                    },
                    {
                        "name": "Successful Login",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 600,
                    },
                ],
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
            },
            {
                "name": "Multi-Firewall Scan",
                "description": "Same source IP denied on 3+ different firewalls within 5 minutes.",
                "severity": "high",
                "stages": [
                    {
                        "name": "Multi-Device Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 15,
                        "window": 300,
                    },
                ],
                "mitre_tactic": "Reconnaissance",
                "mitre_technique": "T1595 - Active Scanning",
            },
            {
                "name": "Denied then Allowed - Same Source",
                "description": "Source IP denied multiple times then allowed through. Possible policy bypass or misconfiguration.",
                "severity": "medium",
                "stages": [
                    {
                        "name": "Repeated Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 5,
                        "window": 600,
                    },
                    {
                        "name": "Access Granted",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 900,
                    },
                ],
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1562 - Impair Defenses",
            },
            {
                "name": "High Volume Outbound Traffic",
                "description": "Single internal IP sending unusually high volume of outbound traffic, potential data exfiltration.",
                "severity": "high",
                "stages": [
                    {
                        "name": "High Outbound Volume",
                        "filter": {"action": "allow", "group_by": "srcip"},
                        "threshold": 500,
                        "window": 300,
                    },
                ],
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
            },
        ]

        added = 0
        for rule_data in rules:
            if rule_data["name"] not in existing:
                rule = CorrelationRule(
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=rule_data["severity"],
                    stages=rule_data["stages"],
                    mitre_tactic=rule_data.get("mitre_tactic"),
                    mitre_technique=rule_data.get("mitre_technique"),
                    is_enabled=True,
                )
                db.add(rule)
                added += 1

        if added > 0:
            await db.commit()
            logger.info(f"Seeded {added} correlation rules")
