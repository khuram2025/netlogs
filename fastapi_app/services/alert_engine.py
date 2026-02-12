"""
Alert Evaluation Engine - evaluates alert rules against ClickHouse log data.

Runs every 30 seconds via the scheduler. Supports:
- Threshold evaluation: count-based conditions (e.g., >100 denied in 5 min)
- Pattern evaluation: multi-condition matching
- Absence evaluation: device stops sending logs
- Anomaly evaluation: compare current vs baseline metrics
"""

import asyncio
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import async_session_maker
from ..db.clickhouse import ClickHouseClient
from ..models.alert import Alert, AlertRule, AlertRuleNotification, NotificationChannel
from .notification_service import send_notification

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=2)


async def evaluate_all_rules():
    """Main evaluation loop - runs all enabled alert rules."""
    logger.debug("Starting alert rule evaluation cycle")
    start_time = datetime.now(timezone.utc)

    async with async_session_maker() as db:
        try:
            # Get all enabled rules
            result = await db.execute(
                select(AlertRule).where(AlertRule.is_enabled == True)
            )
            rules = result.scalars().all()

            if not rules:
                logger.debug("No enabled alert rules to evaluate")
                return

            triggered_count = 0
            error_count = 0

            for rule in rules:
                try:
                    triggered = await _evaluate_rule(rule, db)
                    if triggered:
                        triggered_count += 1
                except Exception as e:
                    error_count += 1
                    logger.error(f"Error evaluating rule '{rule.name}' (id={rule.id}): {e}")
                    logger.debug(traceback.format_exc())

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if triggered_count > 0 or error_count > 0:
                logger.info(
                    f"Alert evaluation completed in {elapsed:.1f}s: "
                    f"{len(rules)} rules, {triggered_count} triggered, {error_count} errors"
                )

        except Exception as e:
            logger.error(f"Fatal error in alert evaluation: {e}")
            logger.debug(traceback.format_exc())


async def _evaluate_rule(rule: AlertRule, db: AsyncSession) -> bool:
    """Evaluate a single alert rule. Returns True if alert was triggered."""

    # Check cooldown
    if rule.last_triggered_at:
        cooldown_until = rule.last_triggered_at + timedelta(minutes=rule.cooldown_minutes or 15)
        if datetime.now(timezone.utc) < cooldown_until:
            return False

    # Dispatch to the appropriate evaluator
    condition_type = rule.condition_type
    config = rule.condition_config or {}

    if condition_type == "threshold":
        result = await _evaluate_threshold(config)
    elif condition_type == "pattern":
        result = await _evaluate_pattern(config)
    elif condition_type == "absence":
        result = await _evaluate_absence(config)
    elif condition_type == "anomaly":
        result = await _evaluate_anomaly(config)
    else:
        logger.warning(f"Unknown condition type '{condition_type}' for rule '{rule.name}'")
        return False

    if not result["triggered"]:
        return False

    # Create alert
    alert = Alert(
        rule_id=rule.id,
        severity=rule.severity,
        title=_build_alert_title(rule, result),
        description=_build_alert_description(rule, result),
        details=result.get("details", {}),
        status="new",
        triggered_at=datetime.now(timezone.utc),
    )
    db.add(alert)

    # Update rule's last_triggered_at
    rule.last_triggered_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(alert)

    logger.info(f"Alert triggered: '{alert.title}' (severity={alert.severity}, rule='{rule.name}')")

    # Send notifications
    await _dispatch_notifications(rule, alert, db)

    return True


async def _evaluate_threshold(config: dict) -> dict:
    """Evaluate a threshold-based rule.

    Config example:
    {
        "field": "action",
        "value": "deny",
        "operator": "count",
        "threshold": 100,
        "window_minutes": 5,
        "group_by": "srcip"
    }
    """
    field = config.get("field", "action")
    value = config.get("value", "")
    threshold = config.get("threshold", 100)
    window = config.get("window_minutes", 5)
    group_by = config.get("group_by")

    loop = asyncio.get_event_loop()

    try:
        def _query():
            client = ClickHouseClient.get_client()

            where_parts = [f"timestamp >= now() - INTERVAL {window} MINUTE"]

            # Build the field condition
            if field and value:
                if "|" in value:
                    values = [v.strip() for v in value.split("|")]
                    placeholders = ", ".join(f"'{v}'" for v in values)
                    where_parts.append(f"{field} IN ({placeholders})")
                else:
                    where_parts.append(f"{field} = '{value}'")

            where_clause = " AND ".join(where_parts)

            if group_by:
                query = f"""
                    SELECT {group_by} as grp, count(*) as cnt
                    FROM syslogs
                    WHERE {where_clause}
                    GROUP BY {group_by}
                    HAVING cnt >= {threshold}
                    ORDER BY cnt DESC
                    LIMIT 10
                """
            else:
                query = f"""
                    SELECT count(*) as cnt
                    FROM syslogs
                    WHERE {where_clause}
                """

            result = client.query(query)
            return result.result_rows

        rows = await loop.run_in_executor(_executor, _query)

        if group_by:
            # Filter out empty group values
            valid_rows = [r for r in rows if str(r[0]).strip()]
            if valid_rows:
                details = {
                    "condition": f"{field}={value}, group_by={group_by}" if value else f"group_by={group_by}",
                    "threshold": threshold,
                    "window_minutes": window,
                    "matches": [{"group": str(r[0]), "count": r[1]} for r in valid_rows],
                }
                # Build where_parts for enrichment
                enrich_where = [f"timestamp >= now() - INTERVAL {window} MINUTE"]
                if field and value:
                    if "|" in value:
                        vals = ", ".join(f"'{v.strip()}'" for v in value.split("|"))
                        enrich_where.append(f"{field} IN ({vals})")
                    else:
                        enrich_where.append(f"{field} = '{value}'")
                details = await loop.run_in_executor(
                    _executor, _enrich_alert_details, enrich_where, window, details
                )
                return {"triggered": True, "details": details}
            # If only empty groups matched, still check total count
            if rows:
                total = sum(r[1] for r in rows)
                if total >= threshold:
                    details = {
                        "condition": f"{field}={value}, group_by={group_by}" if value else f"group_by={group_by}",
                        "threshold": threshold,
                        "window_minutes": window,
                        "matches": [{"group": "unresolved", "count": total}],
                    }
                    enrich_where = [f"timestamp >= now() - INTERVAL {window} MINUTE"]
                    if field and value:
                        if "|" in value:
                            vals = ", ".join(f"'{v.strip()}'" for v in value.split("|"))
                            enrich_where.append(f"{field} IN ({vals})")
                        else:
                            enrich_where.append(f"{field} = '{value}'")
                    details = await loop.run_in_executor(
                        _executor, _enrich_alert_details, enrich_where, window, details
                    )
                    return {"triggered": True, "details": details}
            return {"triggered": False}
        else:
            count = rows[0][0] if rows else 0
            if count >= threshold:
                details = {
                    "condition": f"{field}={value}" if value else "all events",
                    "threshold": threshold,
                    "window_minutes": window,
                    "count": count,
                }
                enrich_where = [f"timestamp >= now() - INTERVAL {window} MINUTE"]
                if field and value:
                    if "|" in value:
                        vals = ", ".join(f"'{v.strip()}'" for v in value.split("|"))
                        enrich_where.append(f"{field} IN ({vals})")
                    else:
                        enrich_where.append(f"{field} = '{value}'")
                details = await loop.run_in_executor(
                    _executor, _enrich_alert_details, enrich_where, window, details
                )
                return {"triggered": True, "details": details}
            return {"triggered": False}

    except Exception as e:
        logger.error(f"Threshold evaluation error: {e}")
        return {"triggered": False}


async def _evaluate_pattern(config: dict) -> dict:
    """Evaluate a pattern-based rule (multi-condition).

    Config example:
    {
        "rules": [
            {"field": "action", "value": "deny"},
            {"field": "dstport", "value": "22"}
        ],
        "threshold": 10,
        "window_minutes": 5,
        "group_by": "srcip"
    }
    """
    rules = config.get("rules", [])
    threshold = config.get("threshold", 10)
    window = config.get("window_minutes", 5)
    group_by = config.get("group_by", "srcip")

    if not rules:
        return {"triggered": False}

    loop = asyncio.get_event_loop()

    try:
        def _query():
            client = ClickHouseClient.get_client()

            where_parts = [f"timestamp >= now() - INTERVAL {window} MINUTE"]

            for rule_cond in rules:
                field = rule_cond.get("field", "")
                value = rule_cond.get("value", "")
                op = rule_cond.get("operator", "=")

                if not field or not value:
                    continue

                if "|" in value:
                    values = [v.strip() for v in value.split("|")]
                    placeholders = ", ".join(f"'{v}'" for v in values)
                    where_parts.append(f"{field} IN ({placeholders})")
                elif op == "!=":
                    where_parts.append(f"{field} != '{value}'")
                elif op == ">":
                    where_parts.append(f"{field} > {value}")
                elif op == "<":
                    where_parts.append(f"{field} < {value}")
                else:
                    where_parts.append(f"{field} = '{value}'")

            where_clause = " AND ".join(where_parts)

            if group_by:
                query = f"""
                    SELECT {group_by} as grp, count(*) as cnt
                    FROM syslogs
                    WHERE {where_clause}
                    GROUP BY {group_by}
                    HAVING cnt >= {threshold}
                    ORDER BY cnt DESC
                    LIMIT 10
                """
            else:
                query = f"""
                    SELECT count(*) as cnt
                    FROM syslogs
                    WHERE {where_clause}
                """

            result = client.query(query)
            return result.result_rows

        rows = await loop.run_in_executor(_executor, _query)

        # Build enrichment WHERE parts (reuse the same conditions)
        enrich_where = [f"timestamp >= now() - INTERVAL {window} MINUTE"]
        for rule_cond in rules:
            f = rule_cond.get("field", "")
            v = rule_cond.get("value", "")
            if not f or not v:
                continue
            if "|" in v:
                vals = ", ".join(f"'{x.strip()}'" for x in v.split("|"))
                enrich_where.append(f"{f} IN ({vals})")
            else:
                enrich_where.append(f"{f} = '{v}'")

        conditions_str = [f"{r['field']}={r['value']}" for r in rules if r.get('field') and r.get('value')]

        if group_by:
            valid_rows = [r for r in rows if str(r[0]).strip()]
            if valid_rows:
                details = {
                    "conditions": conditions_str,
                    "threshold": threshold,
                    "window_minutes": window,
                    "matches": [{"group": str(r[0]), "count": r[1]} for r in valid_rows],
                }
                details = await loop.run_in_executor(
                    _executor, _enrich_alert_details, enrich_where, window, details
                )
                return {"triggered": True, "details": details}
            return {"triggered": False}
        else:
            count = rows[0][0] if rows else 0
            if count >= threshold:
                details = {
                    "conditions": conditions_str,
                    "threshold": threshold,
                    "window_minutes": window,
                    "count": count,
                }
                details = await loop.run_in_executor(
                    _executor, _enrich_alert_details, enrich_where, window, details
                )
                return {"triggered": True, "details": details}
            return {"triggered": False}

    except Exception as e:
        logger.error(f"Pattern evaluation error: {e}")
        return {"triggered": False}


async def _evaluate_absence(config: dict) -> dict:
    """Evaluate an absence-based rule (device stopped sending logs).

    Config example:
    {
        "device_ip": "192.168.100.102",
        "timeout_minutes": 10
    }
    """
    device_ip = config.get("device_ip", "")
    timeout = config.get("timeout_minutes", 10)

    if not device_ip:
        return {"triggered": False}

    loop = asyncio.get_event_loop()

    try:
        def _query():
            client = ClickHouseClient.get_client()
            query = f"""
                SELECT max(timestamp) as last_log
                FROM syslogs
                WHERE device_ip = toIPv4('{device_ip}')
                AND timestamp >= now() - INTERVAL 24 HOUR
            """
            result = client.query(query)
            return result.result_rows

        rows = await loop.run_in_executor(_executor, _query)

        if not rows or not rows[0][0]:
            # No logs at all in last 24h
            return {
                "triggered": True,
                "details": {
                    "device_ip": device_ip,
                    "timeout_minutes": timeout,
                    "last_log": None,
                    "message": f"No logs from {device_ip} in last 24 hours",
                },
            }

        last_log = rows[0][0]
        if hasattr(last_log, 'tzinfo') and last_log.tzinfo is None:
            # Make aware
            last_log = last_log.replace(tzinfo=timezone.utc)

        age_minutes = (datetime.now(timezone.utc) - last_log).total_seconds() / 60

        if age_minutes >= timeout:
            return {
                "triggered": True,
                "details": {
                    "device_ip": device_ip,
                    "timeout_minutes": timeout,
                    "last_log": last_log.isoformat(),
                    "minutes_since_last": round(age_minutes, 1),
                    "message": f"No logs from {device_ip} for {round(age_minutes)} minutes",
                },
            }

        return {"triggered": False}

    except Exception as e:
        logger.error(f"Absence evaluation error: {e}")
        return {"triggered": False}


async def _evaluate_anomaly(config: dict) -> dict:
    """Evaluate an anomaly-based rule (current vs baseline).

    Config example:
    {
        "metric": "eps",
        "multiplier": 3,
        "window_minutes": 5,
        "baseline_hours": 24
    }
    """
    metric = config.get("metric", "eps")  # events per second
    multiplier = config.get("multiplier", 3)
    window = config.get("window_minutes", 5)
    baseline_hours = config.get("baseline_hours", 24)

    loop = asyncio.get_event_loop()

    try:
        def _query():
            client = ClickHouseClient.get_client()

            # Current rate
            current_query = f"""
                SELECT count(*) / ({window} * 60) as current_eps
                FROM syslogs
                WHERE timestamp >= now() - INTERVAL {window} MINUTE
            """
            current_result = client.query(current_query)
            current_eps = current_result.result_rows[0][0] if current_result.result_rows else 0

            # Baseline rate (same hour over baseline period, excluding current window)
            baseline_query = f"""
                SELECT count(*) / ({baseline_hours} * 3600) as baseline_eps
                FROM syslogs
                WHERE timestamp >= now() - INTERVAL {baseline_hours} HOUR
                AND timestamp < now() - INTERVAL {window} MINUTE
            """
            baseline_result = client.query(baseline_query)
            baseline_eps = baseline_result.result_rows[0][0] if baseline_result.result_rows else 0

            return current_eps, baseline_eps

        current_eps, baseline_eps = await loop.run_in_executor(_executor, _query)

        if baseline_eps > 0 and current_eps >= baseline_eps * multiplier:
            return {
                "triggered": True,
                "details": {
                    "metric": metric,
                    "current_eps": round(float(current_eps), 2),
                    "baseline_eps": round(float(baseline_eps), 2),
                    "multiplier": multiplier,
                    "ratio": round(float(current_eps / baseline_eps), 2) if baseline_eps > 0 else 0,
                    "message": f"Current EPS ({round(float(current_eps), 1)}) is {round(float(current_eps / baseline_eps), 1)}x the baseline ({round(float(baseline_eps), 1)})",
                },
            }

        return {"triggered": False}

    except Exception as e:
        logger.error(f"Anomaly evaluation error: {e}")
        return {"triggered": False}


def _enrich_alert_details(where_parts: list, window: int, details: dict) -> dict:
    """Enrich alert details with top IPs, ports, devices, and time range.

    Runs additional ClickHouse queries to provide SOC-analyst-friendly context.
    """
    try:
        client = ClickHouseClient.get_client()
        where_clause = " AND ".join(where_parts)

        # Query: top source IPs with destination and device context
        src_query = f"""
            SELECT srcip, toString(device_ip) as dev,
                   count(*) as cnt,
                   min(timestamp) as first_seen,
                   max(timestamp) as last_seen
            FROM syslogs
            WHERE {where_clause} AND srcip != ''
            GROUP BY srcip, device_ip
            ORDER BY cnt DESC
            LIMIT 15
        """
        src_rows = client.query(src_query).result_rows

        # Query: top destination IPs and ports
        dst_query = f"""
            SELECT dstip, dstport,
                   count(*) as cnt
            FROM syslogs
            WHERE {where_clause} AND dstip != ''
            GROUP BY dstip, dstport
            ORDER BY cnt DESC
            LIMIT 15
        """
        dst_rows = client.query(dst_query).result_rows

        # Query: top destination ports alone
        port_query = f"""
            SELECT dstport, count(*) as cnt
            FROM syslogs
            WHERE {where_clause} AND dstport > 0
            GROUP BY dstport
            ORDER BY cnt DESC
            LIMIT 10
        """
        port_rows = client.query(port_query).result_rows

        # Query: overall time range and total
        summary_query = f"""
            SELECT count(*) as total,
                   min(timestamp) as first_seen,
                   max(timestamp) as last_seen
            FROM syslogs
            WHERE {where_clause}
        """
        summary_rows = client.query(summary_query).result_rows

        # Aggregate top sources (merge device info per IP)
        src_map = {}
        for row in src_rows:
            ip = str(row[0])
            dev = str(row[1])
            cnt = row[2]
            if ip in src_map:
                src_map[ip]["count"] += cnt
                if dev and dev not in src_map[ip]["devices"]:
                    src_map[ip]["devices"].append(dev)
            else:
                src_map[ip] = {"ip": ip, "count": cnt, "devices": [dev] if dev else []}
        top_sources = sorted(src_map.values(), key=lambda x: x["count"], reverse=True)[:10]

        # Aggregate top destinations
        dst_map = {}
        for row in dst_rows:
            ip = str(row[0])
            port = int(row[1])
            cnt = row[2]
            key = f"{ip}:{port}"
            if key not in dst_map:
                dst_map[key] = {"ip": ip, "port": port, "count": cnt}
            else:
                dst_map[key]["count"] += cnt
        top_destinations = sorted(dst_map.values(), key=lambda x: x["count"], reverse=True)[:10]

        # Top ports
        top_ports = [{"port": int(r[0]), "count": r[1]} for r in port_rows]

        # All devices involved
        all_devices = list({str(r[1]) for r in src_rows if str(r[1])})

        # Time range
        total_events = summary_rows[0][0] if summary_rows else 0
        first_seen = summary_rows[0][1] if summary_rows and summary_rows[0][1] else None
        last_seen = summary_rows[0][2] if summary_rows and summary_rows[0][2] else None

        details["top_sources"] = top_sources
        details["top_destinations"] = top_destinations
        details["top_ports"] = top_ports
        details["devices"] = all_devices
        details["total_events"] = total_events
        details["time_range"] = {
            "first": first_seen.isoformat() if hasattr(first_seen, 'isoformat') else str(first_seen) if first_seen else None,
            "last": last_seen.isoformat() if hasattr(last_seen, 'isoformat') else str(last_seen) if last_seen else None,
        }

    except Exception as e:
        logger.warning(f"Alert enrichment failed (non-fatal): {e}")

    return details


def _build_alert_title(rule: AlertRule, result: dict) -> str:
    """Build human-readable alert title."""
    details = result.get("details", {})

    if rule.condition_type == "absence":
        device_ip = details.get("device_ip", "unknown")
        return f"Device Offline: {device_ip}"

    if rule.condition_type == "anomaly":
        return f"Anomaly Detected: {details.get('message', rule.name)}"

    # For threshold/pattern, include top source → top destination with event count
    top_sources = details.get("top_sources", [])
    top_destinations = details.get("top_destinations", [])
    total = details.get("total_events", 0)

    if top_sources:
        src_ip = top_sources[0]["ip"]
        if top_destinations:
            dst_ip = top_destinations[0]["ip"]
            return f"{rule.name}: {src_ip} \u2192 {dst_ip} ({total} events)"
        return f"{rule.name}: {src_ip} ({total} events)"

    # Fallback to old-style matches
    matches = details.get("matches", [])
    if matches:
        top = matches[0]
        grp = top.get("group", "")
        if grp:
            return f"{rule.name}: {grp} ({top['count']} events)"

    count = details.get("count", 0) or details.get("total_events", 0)
    if count:
        return f"{rule.name}: {count} events detected"

    return rule.name


def _build_alert_description(rule: AlertRule, result: dict) -> str:
    """Build human-readable alert description."""
    details = result.get("details", {})
    parts = []

    if rule.description:
        parts.append(rule.description)

    msg = details.get("message")
    if msg:
        parts.append(msg)

    # Add device context
    devices = details.get("devices", [])
    if devices:
        parts.append(f"Devices: {', '.join(devices[:5])}")

    # Add top source summary
    top_sources = details.get("top_sources", [])
    if top_sources:
        src_lines = [f"  {s['ip']} ({s['count']} events)" for s in top_sources[:5]]
        parts.append("Top Sources:\n" + "\n".join(src_lines))

    if rule.mitre_tactic:
        parts.append(f"MITRE ATT&CK: {rule.mitre_tactic}")
    if rule.mitre_technique:
        parts.append(f"Technique: {rule.mitre_technique}")

    return "\n".join(parts) if parts else None


async def _dispatch_notifications(rule: AlertRule, alert: Alert, db: AsyncSession):
    """Send notifications for a triggered alert to all configured channels."""
    try:
        result = await db.execute(
            select(NotificationChannel)
            .join(AlertRuleNotification, AlertRuleNotification.channel_id == NotificationChannel.id)
            .where(
                AlertRuleNotification.rule_id == rule.id,
                NotificationChannel.is_enabled == True,
            )
        )
        channels = result.scalars().all()

        for channel in channels:
            try:
                success = await send_notification(channel, alert, rule)
                if success:
                    channel.last_sent_at = datetime.now(timezone.utc)
                    await db.commit()
            except Exception as e:
                logger.error(f"Failed to send notification via '{channel.name}': {e}")

    except Exception as e:
        logger.error(f"Error dispatching notifications for alert {alert.id}: {e}")


async def test_rule_dry_run(rule_id: int) -> dict:
    """Dry-run a rule against the last hour of data without creating alerts.

    Returns:
        Dict with 'would_trigger', 'details', and 'matches' keys.
    """
    async with async_session_maker() as db:
        result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
        rule = result.scalar_one_or_none()

        if not rule:
            return {"success": False, "error": "Rule not found"}

        config = rule.condition_config or {}

        # Override window to 60 minutes for dry run
        config_copy = dict(config)
        if "window_minutes" in config_copy:
            config_copy["window_minutes"] = 60

        if rule.condition_type == "threshold":
            eval_result = await _evaluate_threshold(config_copy)
        elif rule.condition_type == "pattern":
            eval_result = await _evaluate_pattern(config_copy)
        elif rule.condition_type == "absence":
            eval_result = await _evaluate_absence(config_copy)
        elif rule.condition_type == "anomaly":
            eval_result = await _evaluate_anomaly(config_copy)
        else:
            return {"success": False, "error": f"Unknown condition type: {rule.condition_type}"}

        return {
            "success": True,
            "would_trigger": eval_result.get("triggered", False),
            "details": eval_result.get("details", {}),
            "rule_name": rule.name,
            "severity": rule.severity,
        }
