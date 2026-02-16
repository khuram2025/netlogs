"""
Correlation Rules management routes.
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.correlation import CorrelationRule
from ..models.alert import AlertRule
from ..core.permissions import require_min_role
from ..core.mitre_attack import TACTICS, TECHNIQUES

logger = logging.getLogger(__name__)

router = APIRouter(tags=["correlation"])

templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = 0
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


# ============================================================
# Correlation Rules UI
# ============================================================

@router.get("/correlation/", response_class=HTMLResponse, name="correlation_rules_page",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def correlation_rules_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Correlation rules management page."""
    # Get all rules
    result = await db.execute(select(CorrelationRule).order_by(CorrelationRule.id))
    rules = result.scalars().all()

    # Get recent matches from ClickHouse
    recent_matches = []
    match_stats = {"total": 0, "today": 0, "critical": 0, "high": 0}
    rule_match_counts = {}
    try:
        client = ClickHouseClient.get_client()
        # Total matches
        r = client.query("SELECT count() FROM correlation_matches")
        match_stats["total"] = r.result_rows[0][0] if r.result_rows else 0

        # Today's matches
        r = client.query("SELECT count() FROM correlation_matches WHERE toDate(timestamp) = today()")
        match_stats["today"] = r.result_rows[0][0] if r.result_rows else 0

        # By severity
        r = client.query("SELECT severity, count() FROM correlation_matches GROUP BY severity")
        for row in r.result_rows:
            if row[0] == "critical":
                match_stats["critical"] = row[1]
            elif row[0] == "high":
                match_stats["high"] = row[1]

        # Per-rule 24h match counts
        r = client.query("""
            SELECT rule_name, count()
            FROM correlation_matches
            WHERE timestamp > now() - INTERVAL 24 HOUR
            GROUP BY rule_name
        """)
        for row in r.result_rows:
            rule_match_counts[row[0]] = row[1]

        # Recent matches
        r = client.query("""
            SELECT timestamp, rule_name, severity, stages_matched, total_stages,
                   key_value, total_events, mitre_tactic, mitre_technique
            FROM correlation_matches
            ORDER BY timestamp DESC
            LIMIT 20
        """)
        for row in r.result_rows:
            recent_matches.append({
                "timestamp": row[0],
                "rule_name": row[1],
                "severity": row[2],
                "stages_matched": row[3],
                "total_stages": row[4],
                "key_value": row[5],
                "total_events": row[6],
                "mitre_tactic": row[7],
                "mitre_technique": row[8],
            })
    except Exception as e:
        logger.error(f"Error fetching correlation matches: {e}")

    return _render("correlation/rules.html", request, {
        "rules": rules,
        "recent_matches": recent_matches,
        "match_stats": match_stats,
        "rule_match_counts": rule_match_counts,
    })


# ============================================================
# JSON API Endpoints
# ============================================================

@router.get("/api/correlation/rules/", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_rules(db: AsyncSession = Depends(get_db)):
    """List all correlation rules."""
    result = await db.execute(select(CorrelationRule).order_by(CorrelationRule.id))
    rules = result.scalars().all()
    return [{
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "severity": r.severity,
        "is_enabled": r.is_enabled,
        "stages": r.stages,
        "mitre_tactic": r.mitre_tactic,
        "mitre_technique": r.mitre_technique,
        "trigger_count": r.trigger_count or 0,
        "last_evaluated_at": str(r.last_evaluated_at) if r.last_evaluated_at else None,
        "last_triggered_at": str(r.last_triggered_at) if r.last_triggered_at else None,
    } for r in rules]


@router.post("/api/correlation/rules/", dependencies=[Depends(require_min_role("ADMIN"))])
async def api_create_rule(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new correlation rule."""
    data = await request.json()
    try:
        rule = CorrelationRule(
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "high"),
            stages=data["stages"],
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            is_enabled=data.get("is_enabled", True),
        )
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        return {"status": "ok", "id": rule.id}
    except Exception as e:
        await db.rollback()
        return JSONResponse(status_code=400, content={"detail": str(e)})


@router.post("/api/correlation/rules/{rule_id}/toggle", dependencies=[Depends(require_min_role("ADMIN"))])
async def api_toggle_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Toggle a correlation rule enabled/disabled."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse(status_code=404, content={"detail": "Rule not found"})
    rule.is_enabled = not rule.is_enabled
    await db.commit()
    return {"status": "ok", "is_enabled": rule.is_enabled}


@router.delete("/api/correlation/rules/{rule_id}", dependencies=[Depends(require_min_role("ADMIN"))])
async def api_delete_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a correlation rule."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse(status_code=404, content={"detail": "Rule not found"})
    await db.delete(rule)
    await db.commit()
    return {"status": "ok"}


@router.get("/correlation/mitre/", response_class=HTMLResponse, name="mitre_attack_map",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def mitre_attack_map(request: Request, db: AsyncSession = Depends(get_db)):
    """MITRE ATT&CK matrix heat map page."""
    # Get all alert rules with MITRE mappings
    alert_result = await db.execute(
        select(AlertRule).where(AlertRule.mitre_technique.isnot(None))
    )
    alert_rules = alert_result.scalars().all()

    # Get all correlation rules with MITRE mappings
    corr_result = await db.execute(
        select(CorrelationRule).where(CorrelationRule.mitre_technique.isnot(None))
    )
    corr_rules = corr_result.scalars().all()

    # Build coverage map: technique_id -> list of rules covering it
    coverage = {}
    for rule in alert_rules:
        tech_id = rule.mitre_technique
        if tech_id:
            # Handle "T1110" or "T1110 - Brute Force" format
            tech_id_clean = tech_id.split(" ")[0].strip()
            if tech_id_clean not in coverage:
                coverage[tech_id_clean] = []
            coverage[tech_id_clean].append({
                "name": rule.name,
                "type": "alert",
                "severity": rule.severity,
                "enabled": rule.is_enabled,
            })

    for rule in corr_rules:
        tech_id = rule.mitre_technique
        if tech_id:
            tech_id_clean = tech_id.split(" ")[0].strip()
            if tech_id_clean not in coverage:
                coverage[tech_id_clean] = []
            coverage[tech_id_clean].append({
                "name": rule.name,
                "type": "correlation",
                "severity": rule.severity,
                "enabled": rule.is_enabled,
            })

    # Calculate stats per tactic
    tactic_stats = []
    total_techniques = 0
    total_covered = 0
    total_detectable = 0
    for tactic in TACTICS:
        techniques = TECHNIQUES.get(tactic["name"], [])
        detectable = [t for t in techniques if t.get("detectable")]
        covered = [t for t in techniques if t["id"].split(" ")[0] in coverage]
        tactic_stats.append({
            "id": tactic["id"],
            "name": tactic["name"],
            "description": tactic["description"],
            "techniques": techniques,
            "total": len(techniques),
            "detectable": len(detectable),
            "covered": len(covered),
            "pct": round(len(covered) / len(detectable) * 100) if detectable else 0,
        })
        total_techniques += len(techniques)
        total_covered += len(covered)
        total_detectable += len(detectable)

    overall_pct = round(total_covered / total_detectable * 100) if total_detectable else 0

    return _render("correlation/mitre_map.html", request, {
        "tactics": TACTICS,
        "techniques": TECHNIQUES,
        "coverage": coverage,
        "tactic_stats": tactic_stats,
        "total_techniques": total_techniques,
        "total_covered": total_covered,
        "total_detectable": total_detectable,
        "overall_pct": overall_pct,
    })


@router.get("/api/correlation/rules/{rule_id}/matches", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_rule_match_detail(rule_id: int, hours: int = 24, db: AsyncSession = Depends(get_db)):
    """Get detailed match data for a specific correlation rule."""
    # Get rule from PostgreSQL
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse(status_code=404, content={"detail": "Rule not found"})

    rule_data = {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "is_enabled": rule.is_enabled,
        "stages": rule.stages,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "trigger_count": rule.trigger_count or 0,
        "last_evaluated_at": str(rule.last_evaluated_at) if rule.last_evaluated_at else None,
        "last_triggered_at": str(rule.last_triggered_at) if rule.last_triggered_at else None,
    }

    match_count = 0
    total_events = 0
    top_keys = []
    timeline = []
    recent_matches = []

    try:
        client = ClickHouseClient.get_client()
        safe_name = rule.name.replace("'", "\\'")
        interval = f"INTERVAL {int(hours)} HOUR"

        # Match count + total events
        r = client.query(f"""
            SELECT count(), sum(total_events)
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - {interval}
        """)
        if r.result_rows:
            match_count = r.result_rows[0][0]
            total_events = r.result_rows[0][1] or 0

        # Top key values (IPs/entities that matched)
        r = client.query(f"""
            SELECT key_value, count() as cnt, sum(total_events) as evts, max(timestamp) as last_seen
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - {interval}
            GROUP BY key_value
            ORDER BY cnt DESC
            LIMIT 15
        """)
        for row in r.result_rows:
            top_keys.append({
                "key_value": row[0],
                "match_count": row[1],
                "total_events": row[2],
                "last_seen": str(row[3]),
            })

        # Hourly timeline
        r = client.query(f"""
            SELECT toStartOfHour(timestamp) as hour, count() as cnt
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - {interval}
            GROUP BY hour
            ORDER BY hour
        """)
        for row in r.result_rows:
            timeline.append({
                "hour": str(row[0]),
                "count": row[1],
            })

        # Recent matches
        r = client.query(f"""
            SELECT timestamp, key_value, stages_matched, total_stages,
                   total_events, severity, stage_details
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - {interval}
            ORDER BY timestamp DESC
            LIMIT 30
        """)
        for row in r.result_rows:
            recent_matches.append({
                "timestamp": str(row[0]),
                "key_value": row[1],
                "stages_matched": row[2],
                "total_stages": row[3],
                "total_events": row[4],
                "severity": row[5],
                "stage_details": row[6],
            })

    except Exception as e:
        logger.error(f"Error fetching rule match details: {e}")

    return {
        "rule": rule_data,
        "match_count": match_count,
        "total_events": total_events,
        "top_keys": top_keys,
        "timeline": timeline,
        "recent_matches": recent_matches,
    }


@router.get("/api/correlation/matches/", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_matches(hours: int = 24, limit: int = 50):
    """List recent correlation matches."""
    try:
        client = ClickHouseClient.get_client()
        result = client.query(f"""
            SELECT timestamp, rule_name, severity, stages_matched, total_stages,
                   stage_details, key_value, total_events, mitre_tactic, mitre_technique
            FROM correlation_matches
            WHERE timestamp > now() - INTERVAL {hours} HOUR
            ORDER BY timestamp DESC
            LIMIT {limit}
        """)
        matches = []
        for row in result.result_rows:
            matches.append({
                "timestamp": str(row[0]),
                "rule_name": row[1],
                "severity": row[2],
                "stages_matched": row[3],
                "total_stages": row[4],
                "stage_details": row[5],
                "key_value": row[6],
                "total_events": row[7],
                "mitre_tactic": row[8],
                "mitre_technique": row[9],
            })
        return matches
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})
