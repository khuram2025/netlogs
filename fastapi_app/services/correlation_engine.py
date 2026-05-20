"""
Correlation Engine - Multi-stage event correlation for detecting complex attack patterns.

Evaluates correlation rules by querying ClickHouse for events matching each stage
in sequence, with variable substitution between stages.
"""

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


def _evaluate_stage(
    stage: dict,
    window_seconds: int,
    variables: dict = None,
    reference_time: str = "now()",
) -> Tuple[bool, dict]:
    """
    Evaluate a single correlation stage against ClickHouse logs.
    Returns (matched: bool, stage_result: dict with key values and event count).
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
            # Aggregation query: find groups exceeding threshold
            query = f"""
                SELECT {group_by}, count() as cnt
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

            return True, {
                "key": top_key,
                "count": top_count,
                group_by: top_key,
                "all_matches": [{"key": str(r[0]), "count": r[1]} for r in rows[:5]],
            }
        else:
            # Simple count query
            query = f"""
                SELECT count() as cnt
                FROM {table}
                WHERE {full_where}
            """
            result = client.query(query, parameters=params)
            count = result.result_rows[0][0] if result.result_rows else 0

            if count >= threshold:
                return True, {"count": count}
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

    for i, stage in enumerate(stages):
        stage_name = stage.get("name", f"Stage {i + 1}")
        window = stage.get("window", 300)

        matched, result = _evaluate_stage(stage, window, variables)

        stage_results.append({
            "name": stage_name,
            "matched": matched,
            "window": window,
            **result,
        })

        if not matched:
            return None  # Chain broken

        # Store variables for next stage
        stage_key = f"stage{i + 1}"
        variables[stage_key] = result
        total_events += result.get("count", 0)

    # All stages matched!
    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "stages": stage_results,
        "total_events": total_events,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "key_value": stage_results[0].get("key", ""),
    }


def record_correlation_match(match: dict):
    """Record a correlation match in ClickHouse."""
    try:
        import json
        client = ClickHouseClient.get_client()
        now = datetime.now(timezone.utc)

        client.insert("correlation_matches",
            [[
                now,
                match["rule_id"],
                match["rule_name"],
                match["severity"],
                len(match["stages"]),
                len(match["stages"]),
                json.dumps(match["stages"], default=str),
                match.get("key_value", ""),
                match.get("total_events", 0),
                match.get("mitre_tactic", ""),
                match.get("mitre_technique", ""),
            ]],
            column_names=[
                "timestamp", "rule_id", "rule_name", "severity",
                "stages_matched", "total_stages", "stage_details",
                "key_value", "total_events", "mitre_tactic", "mitre_technique"
            ]
        )
    except Exception as e:
        logger.error(f"Failed to record correlation match: {e}")


async def create_correlation_alert(match: dict):
    """Create an alert from a correlation match."""
    try:
        async with async_session_maker() as db:
            # Check for recent duplicate alerts (within 5 minutes)
            from sqlalchemy import and_, func
            recent = await db.execute(
                select(func.count(Alert.id)).where(
                    and_(
                        Alert.title.contains(match["rule_name"]),
                        Alert.triggered_at > _recent_alert_cutoff(),
                    )
                )
            )
            if recent.scalar() > 0:
                return  # Avoid duplicate alerts

            import json
            stages_summary = " -> ".join(
                f"{s['name']} ({s.get('count', 0)} events)"
                for s in match["stages"]
            )

            alert = Alert(
                title=f"Correlation: {match['rule_name']} [{match.get('key_value', '')}]",
                severity=match["severity"],
                status="new",
                details=json.dumps({
                    "correlation_rule": match["rule_name"],
                    "stages": match["stages"],
                    "total_events": match["total_events"],
                    "key_value": match.get("key_value", ""),
                    "attack_chain": stages_summary,
                    "mitre_tactic": match.get("mitre_tactic", ""),
                    "mitre_technique": match.get("mitre_technique", ""),
                }, default=str),
                triggered_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            await db.commit()
            logger.info(f"Correlation alert created: {match['rule_name']}")
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
            for rule in rules:
                try:
                    match = evaluate_correlation_rule(rule)
                    if match:
                        matched_count += 1
                        record_correlation_match(match)
                        await create_correlation_alert(match)

                        # Update rule stats
                        rule.last_triggered_at = datetime.now(timezone.utc)
                        rule.trigger_count = (rule.trigger_count or 0) + 1

                    rule.last_evaluated_at = datetime.now(timezone.utc)
                except Exception as e:
                    logger.error(f"Error evaluating correlation rule '{rule.name}': {e}")

            await db.commit()

            if matched_count > 0:
                logger.info(f"Correlation engine: {matched_count} rules triggered out of {len(rules)}")

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
