"""
Correlation Engine - Multi-stage event correlation for detecting complex attack patterns.

Evaluates correlation rules by querying ClickHouse for events matching each stage
in sequence, with variable substitution between stages.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.correlation import CorrelationRule
from ..models.alert import Alert, AlertRule

logger = logging.getLogger(__name__)


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


def _build_where_clause(filter_config: dict, variables: dict = None) -> str:
    """Build a ClickHouse WHERE clause from a stage filter config."""
    conditions = []

    for field, value in filter_config.items():
        if field in ("group_by", "threshold", "window"):
            continue

        # Variable substitution ($stage1.srcip -> actual value)
        if isinstance(value, str) and value.startswith("$"):
            if variables:
                var_parts = value[1:].split(".", 1)
                if len(var_parts) == 2:
                    stage_key, var_field = var_parts
                    resolved = variables.get(stage_key, {}).get(var_field)
                    if resolved:
                        value = resolved
                    else:
                        continue  # Skip if variable not resolved

        # Handle comparison operators
        if field.endswith("_gt"):
            actual_field = field[:-3]
            conditions.append(f"{actual_field} > {value}")
        elif field.endswith("_lt"):
            actual_field = field[:-3]
            conditions.append(f"{actual_field} < {value}")
        elif field.endswith("_gte"):
            actual_field = field[:-4]
            conditions.append(f"{actual_field} >= {value}")
        elif field.endswith("_lte"):
            actual_field = field[:-4]
            conditions.append(f"{actual_field} <= {value}")
        elif field.endswith("_ne"):
            actual_field = field[:-3]
            conditions.append(f"{actual_field} != '{value}'")
        else:
            conditions.append(f"{field} = '{value}'")

    return " AND ".join(conditions) if conditions else "1=1"


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
        filter_config = stage.get("filter", {})
        threshold = stage.get("threshold", 1)
        group_by = filter_config.get("group_by", stage.get("group_by"))

        where = _build_where_clause(filter_config, variables)
        time_filter = f"timestamp > {reference_time} - INTERVAL {window_seconds} SECOND"
        full_where = f"{time_filter} AND {where}"

        if group_by:
            # Aggregation query: find groups exceeding threshold
            query = f"""
                SELECT {group_by}, count() as cnt
                FROM syslogs
                WHERE {full_where}
                GROUP BY {group_by}
                HAVING cnt >= {threshold}
                ORDER BY cnt DESC
                LIMIT 10
            """
            result = client.query(query)
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
                FROM syslogs
                WHERE {full_where}
            """
            result = client.query(query)
            count = result.result_rows[0][0] if result.result_rows else 0

            if count >= threshold:
                return True, {"count": count}
            return False, {"count": count}

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
                        Alert.triggered_at > datetime.now(timezone.utc).replace(
                            minute=datetime.now(timezone.utc).minute - 5
                        ),
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
