"""
Correlation Rules management routes.
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.correlation import CorrelationRule, CorrelationIncident
from ..models.alert import AlertRule
from ..core.permissions import require_min_role
from ..core.mitre_attack import TACTICS, TECHNIQUES
from ..schemas.correlation import CorrelationRuleCreate, CorrelationRuleUpdate

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


def compute_coverage_stats(coverage: dict):
    """Compute MITRE ATT&CK coverage statistics from a technique-id -> rules map.

    ``covered`` counts only **detectable** techniques that have a rule, so the
    coverage percentage is a true subset of ``detectable`` and can never exceed
    100%. (The previous implementation counted *all* covered techniques over a
    *detectable*-only denominator, which could inflate the percentage when a
    non-detectable technique was mapped to a rule.)

    Returns ``(tactic_stats, total_techniques, total_covered,
    total_detectable, overall_pct)``.
    """
    tactic_stats = []
    total_techniques = 0
    total_covered = 0
    total_detectable = 0
    for tactic in TACTICS:
        techniques = TECHNIQUES.get(tactic["name"], [])
        detectable = [t for t in techniques if t.get("detectable")]
        covered = [t for t in techniques
                   if t.get("detectable") and t["id"].split(" ")[0] in coverage]
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
    return tactic_stats, total_techniques, total_covered, total_detectable, overall_pct


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
    match_stats = {"total": 0, "today": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0}
    rule_match_counts = {}
    try:
        client = ClickHouseClient.get_client()
        # Total matches
        r = client.query("SELECT count() FROM correlation_matches")
        match_stats["total"] = r.result_rows[0][0] if r.result_rows else 0

        # Today's matches
        r = client.query("SELECT count() FROM correlation_matches WHERE toDate(timestamp) = today()")
        match_stats["today"] = r.result_rows[0][0] if r.result_rows else 0

        # By severity (critical / high / medium / low)
        r = client.query("SELECT severity, count() FROM correlation_matches GROUP BY severity")
        for row in r.result_rows:
            sev = row[0]
            if sev in match_stats and sev not in ("total", "today"):
                match_stats[sev] = row[1]

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
        "version": getattr(r, "version", 1) or 1,
        "match_mode": getattr(r, "match_mode", "discrete") or "discrete",
        "suppress_window": getattr(r, "suppress_window", 3600) or 3600,
        "ordering": getattr(r, "ordering", "sequence") or "sequence",
        "join_keys": getattr(r, "join_keys", None),
        "schema_version": getattr(r, "schema_version", 2) or 2,
        "trigger_count": r.trigger_count or 0,
        "last_evaluated_at": str(r.last_evaluated_at) if r.last_evaluated_at else None,
        "last_triggered_at": str(r.last_triggered_at) if r.last_triggered_at else None,
    } for r in rules]


@router.post("/api/correlation/rules/", dependencies=[Depends(require_min_role("ADMIN"))])
async def api_create_rule(payload: CorrelationRuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new correlation rule.

    The request body is validated by ``CorrelationRuleCreate`` — a malformed
    rule (bad severity, empty stages, unknown filter field, non-numeric value
    for a numeric field, ...) is rejected with a 422 before it is ever stored.
    """
    try:
        rule = CorrelationRule(
            name=payload.name,
            description=payload.description or "",
            severity=payload.severity,
            stages=[s.model_dump() for s in payload.stages],
            mitre_tactic=payload.mitre_tactic,
            mitre_technique=payload.mitre_technique,
            is_enabled=payload.is_enabled,
            match_mode=payload.match_mode,
            suppress_window=payload.suppress_window,
            ordering=payload.ordering,
            join_keys=payload.join_keys,
        )
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        return {"status": "ok", "id": rule.id}
    except IntegrityError:
        await db.rollback()
        return JSONResponse(status_code=400,
                            content={"detail": f"A rule named '{payload.name}' already exists"})
    except Exception as e:
        await db.rollback()
        return JSONResponse(status_code=400, content={"detail": str(e)})


@router.put("/api/correlation/rules/{rule_id}", dependencies=[Depends(require_min_role("ADMIN"))])
async def api_update_rule(rule_id: int, payload: CorrelationRuleUpdate,
                          db: AsyncSession = Depends(get_db)):
    """Update an existing correlation rule. Only the fields supplied in the
    request body are changed; the rule's identity and history are preserved."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse(status_code=404, content={"detail": "Rule not found"})

    data = payload.model_dump(exclude_unset=True)
    if not data:
        return JSONResponse(status_code=400, content={"detail": "No fields to update"})

    try:
        for field, value in data.items():
            setattr(rule, field, value)
        rule.updated_at = datetime.now(timezone.utc)
        # Bump the version so matches can be tied to the exact rule definition
        # that produced them; this also resets suppression after an edit.
        rule.version = (rule.version or 1) + 1
        await db.commit()
        await db.refresh(rule)
        return {"status": "ok", "id": rule.id, "version": rule.version}
    except IntegrityError:
        await db.rollback()
        return JSONResponse(status_code=400,
                            content={"detail": "A rule with that name already exists"})
    except Exception as e:
        await db.rollback()
        return JSONResponse(status_code=400, content={"detail": str(e)})


@router.post("/api/correlation/rules/{rule_id}/clone",
             dependencies=[Depends(require_min_role("ADMIN"))])
async def api_clone_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Duplicate a correlation rule. The copy is created **disabled** so it can
    be reviewed and tuned before it starts firing."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse(status_code=404, content={"detail": "Rule not found"})

    existing = await db.execute(select(CorrelationRule.name))
    names = {r[0] for r in existing.all()}
    base = f"{rule.name} (copy)"
    new_name = base
    suffix = 2
    while new_name in names:
        new_name = f"{base} {suffix}"
        suffix += 1

    try:
        clone = CorrelationRule(
            name=new_name,
            description=rule.description,
            severity=rule.severity,
            stages=rule.stages,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            is_enabled=False,
        )
        db.add(clone)
        await db.commit()
        await db.refresh(clone)
        return {"status": "ok", "id": clone.id, "name": new_name}
    except Exception as e:
        await db.rollback()
        return JSONResponse(status_code=400, content={"detail": str(e)})


@router.post("/api/correlation/rules/test", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_test_rule(payload: CorrelationRuleCreate):
    """Dry-run a draft correlation rule against recent history.

    Builds a transient (un-persisted) rule and previews it — returns per-stage
    diagnostics, sample matches and a rough fire-rate estimate. Records
    nothing: no match row, no alert. Drives the builder's Test button.
    """
    from ..services.correlation_engine import preview_correlation_rule

    rule = CorrelationRule(
        name=payload.name or "Draft",
        description=payload.description or "",
        severity=payload.severity,
        stages=[s.model_dump() for s in payload.stages],
        mitre_tactic=payload.mitre_tactic,
        mitre_technique=payload.mitre_technique,
        is_enabled=True,
        match_mode=payload.match_mode,
        suppress_window=payload.suppress_window,
        ordering=payload.ordering,
        join_keys=payload.join_keys,
    )
    # Transient object — never added to a session, so nothing is persisted.
    rule.id = 0
    rule.version = 1
    return preview_correlation_rule(rule)


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


@router.get("/api/correlation/schema", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_correlation_schema():
    """Field / operator / source catalog that drives the visual rule builder."""
    from ..core.correlation_fields import SOURCES, CANONICAL_ENTITIES, DEFAULT_SOURCE

    sources = {
        name: {
            "label": src["label"],
            "fields": [{"name": f, "type": t}
                       for f, t in sorted(src["fields"].items())],
            "entities": list(src["entities"].keys()),
        }
        for name, src in SOURCES.items()
    }
    return {
        "sources": sources,
        "default_source": DEFAULT_SOURCE,
        "canonical_entities": CANONICAL_ENTITIES,
        # operator -> field-name suffix the engine understands
        "operators": {
            "string": [
                {"op": "eq", "label": "equals", "suffix": ""},
                {"op": "ne", "label": "not equals", "suffix": "_ne"},
            ],
            "ip": [
                {"op": "eq", "label": "equals", "suffix": ""},
                {"op": "ne", "label": "not equals", "suffix": "_ne"},
            ],
            "numeric": [
                {"op": "eq", "label": "equals", "suffix": ""},
                {"op": "ne", "label": "not equals", "suffix": "_ne"},
                {"op": "gt", "label": "greater than", "suffix": "_gt"},
                {"op": "lt", "label": "less than", "suffix": "_lt"},
                {"op": "gte", "label": "greater or equal", "suffix": "_gte"},
                {"op": "lte", "label": "less or equal", "suffix": "_lte"},
            ],
        },
        "severities": ["critical", "high", "medium", "low"],
        "orderings": ["sequence", "any_order"],
        "match_modes": ["discrete", "recurring"],
    }


@router.get("/api/correlation/templates", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_correlation_templates():
    """Curated correlation rule templates. Each is flagged ``available`` when
    every data source it needs is registered on this deployment — so the UI
    can do data-aware template discovery."""
    from ..core.correlation_templates import TEMPLATES
    from ..core.correlation_fields import SOURCES

    out = []
    for t in TEMPLATES:
        req = t.get("required_sources", [])
        out.append({
            "id": t["id"],
            "name": t["name"],
            "description": t["description"],
            "category": t["category"],
            "mitre_tactic": t.get("mitre_tactic"),
            "mitre_technique": t.get("mitre_technique"),
            "required_sources": req,
            "available": all(s in SOURCES for s in req),
            "rule": t["rule"],
        })
    return out


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
    (tactic_stats, total_techniques, total_covered,
     total_detectable, overall_pct) = compute_coverage_stats(coverage)

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
async def api_rule_match_detail(rule_id: int,
                                hours: int = Query(24, ge=1, le=720),
                                db: AsyncSession = Depends(get_db)):
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
        "version": getattr(rule, "version", 1) or 1,
        "match_mode": getattr(rule, "match_mode", "discrete") or "discrete",
        "suppress_window": getattr(rule, "suppress_window", 3600) or 3600,
        "ordering": getattr(rule, "ordering", "sequence") or "sequence",
        "join_keys": getattr(rule, "join_keys", None),
        "schema_version": getattr(rule, "schema_version", 2) or 2,
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

        # Recent matches — include match-identity & evidence columns
        r = client.query(f"""
            SELECT timestamp, key_value, stages_matched, total_stages,
                   total_events, severity, stage_details,
                   entity_type, entity_value, match_fingerprint,
                   first_seen, last_seen, status
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
                "entity_type": row[7],
                "entity_value": row[8],
                "match_fingerprint": row[9],
                "first_seen": str(row[10]) if row[10] else None,
                "last_seen": str(row[11]) if row[11] else None,
                "status": row[12],
            })

    except Exception as e:
        logger.error(f"Error fetching rule match details: {e}")

    # Phase 6: rule health scorecard — fire frequency over 7/30 days, a
    # 30-day daily timeline, and a dormant/healthy/noisy assessment.
    health = {
        "status": "unknown", "matches_7d": 0, "matches_30d": 0,
        "daily": [], "version": rule_data["version"],
        "last_modified": (str(rule.updated_at) if rule.updated_at else None),
    }
    try:
        client = ClickHouseClient.get_client()
        safe_name = rule.name.replace("'", "\\'")
        r = client.query(f"""
            SELECT countIf(timestamp > now() - INTERVAL 7 DAY) AS w,
                   count() AS m
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - INTERVAL 30 DAY
        """)
        if r.result_rows:
            health["matches_7d"] = r.result_rows[0][0] or 0
            health["matches_30d"] = r.result_rows[0][1] or 0
        r = client.query(f"""
            SELECT toDate(timestamp) AS d, count() AS c
            FROM correlation_matches
            WHERE rule_name = '{safe_name}' AND timestamp > now() - INTERVAL 30 DAY
            GROUP BY d ORDER BY d
        """)
        health["daily"] = [{"day": str(row[0]), "count": row[1]} for row in r.result_rows]

        w7 = health["matches_7d"]
        if w7 == 0:
            health["status"] = "dormant"
        elif w7 > 5000:
            health["status"] = "very noisy"
        elif w7 > 500:
            health["status"] = "noisy"
        else:
            health["status"] = "healthy"
    except Exception as e:
        logger.error(f"Error computing rule health: {e}")

    return {
        "rule": rule_data,
        "match_count": match_count,
        "total_events": total_events,
        "top_keys": top_keys,
        "timeline": timeline,
        "recent_matches": recent_matches,
        "health": health,
    }


@router.get("/api/correlation/matches/", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_matches(hours: int = Query(24, ge=1, le=720),
                           limit: int = Query(50, ge=1, le=500)):
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


# ============================================================
# Incidents (Phase 5)
# ============================================================

_INCIDENT_STATUSES = {"new", "investigating", "contained", "resolved", "suppressed"}


def _incident_dict(inc: CorrelationIncident, include_matches: bool = False) -> dict:
    d = {
        "id": inc.id,
        "entity_type": inc.entity_type,
        "entity_value": inc.entity_value,
        "status": inc.status,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "match_count": inc.match_count,
        "rule_names": inc.rule_names or [],
        "mitre_tactics": inc.mitre_tactics or [],
        "first_seen": str(inc.first_seen) if inc.first_seen else None,
        "last_seen": str(inc.last_seen) if inc.last_seen else None,
    }
    if include_matches:
        d["matches"] = inc.matches or []
    return d


@router.get("/api/correlation/incidents", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_incidents(status: str = Query(None),
                             limit: int = Query(100, ge=1, le=500),
                             db: AsyncSession = Depends(get_db)):
    """List correlation incidents, most recently active first."""
    q = select(CorrelationIncident).order_by(
        desc(CorrelationIncident.last_seen))
    if status and status in _INCIDENT_STATUSES:
        q = q.where(CorrelationIncident.status == status)
    q = q.limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [_incident_dict(i) for i in rows]


@router.get("/api/correlation/incidents/{incident_id}",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_incident_detail(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Get one incident with its contributing-match evidence."""
    inc = (await db.execute(
        select(CorrelationIncident).where(CorrelationIncident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        return JSONResponse(status_code=404, content={"detail": "Incident not found"})
    return _incident_dict(inc, include_matches=True)


@router.post("/api/correlation/incidents/{incident_id}/status",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_incident_status(incident_id: int, request: Request,
                              db: AsyncSession = Depends(get_db)):
    """Move an incident through its lifecycle (new / investigating /
    contained / resolved / suppressed)."""
    data = await request.json()
    new_status = data.get("status")
    if new_status not in _INCIDENT_STATUSES:
        return JSONResponse(status_code=400, content={
            "detail": f"status must be one of {sorted(_INCIDENT_STATUSES)}"})
    inc = (await db.execute(
        select(CorrelationIncident).where(CorrelationIncident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        return JSONResponse(status_code=404, content={"detail": "Incident not found"})
    inc.status = new_status
    inc.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok", "incident_status": new_status}
