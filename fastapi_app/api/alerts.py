"""
Alert routes - dashboard, alert rules, notification channels.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.alert import Alert, AlertRule, NotificationChannel, AlertRuleNotification
from ..models.user import User
from ..core.permissions import require_role, require_min_role
from ..core.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])

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
# Alert Dashboard UI
# ============================================================

@router.get("/alerts/", response_class=HTMLResponse, name="alert_dashboard",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def alert_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Alert dashboard page."""
    # Get alert summary counts
    summary = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        r = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.severity == sev,
                Alert.status.in_(["new", "acknowledged", "investigating"]),
            )
        )
        summary[sev] = r.scalar() or 0

    # Count new (unacknowledged)
    r = await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "new")
    )
    summary["new_count"] = r.scalar() or 0

    # Get recent alerts
    result = await db.execute(
        select(Alert)
        .order_by(desc(Alert.triggered_at))
        .limit(100)
    )
    alerts = result.scalars().all()

    # Get all users for assignment dropdown
    users_result = await db.execute(select(User).where(User.is_active == True).order_by(User.username))
    users = users_result.scalars().all()

    # Get alert rules for filter
    rules_result = await db.execute(select(AlertRule).order_by(AlertRule.name))
    rules = rules_result.scalars().all()

    return _render("alerts/alert_dashboard.html", request, {
        "alerts": alerts,
        "summary": summary,
        "users": users,
        "rules": rules,
    })


# ============================================================
# Alerts API
# ============================================================

@router.get("/api/alerts/", name="api_alert_list",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_alert_list(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_id: Optional[int] = None,
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with filters."""
    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)

    query = query.order_by(desc(Alert.triggered_at)).limit(limit).offset(offset)

    result = await db.execute(query)
    alerts = result.scalars().all()

    # Count total
    count_query = select(func.count(Alert.id))
    if severity:
        count_query = count_query.where(Alert.severity == severity)
    if status:
        count_query = count_query.where(Alert.status == status)
    if rule_id:
        count_query = count_query.where(Alert.rule_id == rule_id)

    total = (await db.execute(count_query)).scalar() or 0

    return JSONResponse({
        "success": True,
        "total": total,
        "alerts": [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "details": a.details,
                "status": a.status,
                "assigned_to": a.assigned_to,
                "triggered_at": a.triggered_at.isoformat() if a.triggered_at else None,
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "resolution_notes": a.resolution_notes,
            }
            for a in alerts
        ],
    })


@router.get("/api/alerts/{alert_id}", name="api_alert_detail",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_alert_detail(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Get alert detail with rule context."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        return JSONResponse({"success": False, "error": "Alert not found"}, status_code=404)

    # Fetch associated rule for context
    rule_name = None
    rule_type = None
    rule_category = None
    if alert.rule_id:
        rule_result = await db.execute(select(AlertRule).where(AlertRule.id == alert.rule_id))
        rule = rule_result.scalar_one_or_none()
        if rule:
            rule_name = rule.name
            rule_type = rule.condition_type
            rule_category = rule.category

    return JSONResponse({
        "success": True,
        "alert": {
            "id": alert.id,
            "rule_id": alert.rule_id,
            "rule_name": rule_name,
            "rule_type": rule_type,
            "rule_category": rule_category,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "details": alert.details,
            "status": alert.status,
            "assigned_to": alert.assigned_to,
            "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "resolved_by": alert.resolved_by,
            "resolution_notes": alert.resolution_notes,
        },
    })


@router.post("/api/alerts/{alert_id}/acknowledge", name="api_acknowledge_alert",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_acknowledge_alert(alert_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Acknowledge an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return JSONResponse({"success": False, "error": "Alert not found"}, status_code=404)

    user = getattr(request.state, "current_user", None)
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    if user:
        alert.assigned_to = user.id
    await db.commit()

    return JSONResponse({"success": True, "message": "Alert acknowledged"})


@router.post("/api/alerts/{alert_id}/assign", name="api_assign_alert",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_assign_alert(alert_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Assign alert to a user."""
    body = await request.json()
    user_id = body.get("user_id")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return JSONResponse({"success": False, "error": "Alert not found"}, status_code=404)

    alert.assigned_to = user_id
    if alert.status == "new":
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()

    return JSONResponse({"success": True, "message": "Alert assigned"})


@router.post("/api/alerts/{alert_id}/resolve", name="api_resolve_alert",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_resolve_alert(alert_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Resolve an alert with notes."""
    body = await request.json()
    notes = body.get("notes", "")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return JSONResponse({"success": False, "error": "Alert not found"}, status_code=404)

    user = getattr(request.state, "current_user", None)
    alert.status = "resolved"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = user.id if user else None
    alert.resolution_notes = notes
    await db.commit()

    return JSONResponse({"success": True, "message": "Alert resolved"})


@router.post("/api/alerts/{alert_id}/false-positive", name="api_false_positive",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_false_positive(alert_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Mark alert as false positive."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        return JSONResponse({"success": False, "error": "Alert not found"}, status_code=404)

    user = getattr(request.state, "current_user", None)
    alert.status = "false_positive"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = user.id if user else None
    await db.commit()

    return JSONResponse({"success": True, "message": "Alert marked as false positive"})


# ============================================================
# Alert Rules API
# ============================================================

@router.get("/alerts/rules/", response_class=HTMLResponse, name="alert_rules_page",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def alert_rules_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Alert rules management page."""
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()

    # Get trigger counts per rule
    trigger_counts = {}
    for rule in rules:
        r = await db.execute(select(func.count(Alert.id)).where(Alert.rule_id == rule.id))
        trigger_counts[rule.id] = r.scalar() or 0

    # Get notification channels
    channels_result = await db.execute(select(NotificationChannel).order_by(NotificationChannel.name))
    channels = channels_result.scalars().all()

    return _render("alerts/alert_rules.html", request, {
        "rules": rules,
        "trigger_counts": trigger_counts,
        "channels": channels,
    })


@router.get("/api/alert-rules/", name="api_alert_rules_list",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_alert_rules_list(db: AsyncSession = Depends(get_db)):
    """List all alert rules."""
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()

    return JSONResponse({
        "success": True,
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "category": r.category,
                "is_enabled": r.is_enabled,
                "condition_type": r.condition_type,
                "condition_config": r.condition_config,
                "cooldown_minutes": r.cooldown_minutes,
                "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique": r.mitre_technique,
            }
            for r in rules
        ],
    })


@router.post("/api/alert-rules/", name="api_create_alert_rule",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_create_alert_rule(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new alert rule."""
    body = await request.json()
    user = getattr(request.state, "current_user", None)

    name = body.get("name", "").strip()
    if not name:
        return JSONResponse({"success": False, "error": "Name is required"}, status_code=400)

    rule = AlertRule(
        name=name,
        description=body.get("description", ""),
        severity=body.get("severity", "medium"),
        category=body.get("category", ""),
        is_enabled=body.get("is_enabled", True),
        condition_type=body.get("condition_type", "threshold"),
        condition_config=body.get("condition_config", {}),
        cooldown_minutes=body.get("cooldown_minutes", 15),
        mitre_tactic=body.get("mitre_tactic", ""),
        mitre_technique=body.get("mitre_technique", ""),
        created_by=user.id if user else None,
    )

    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Add notification channel mappings
    channel_ids = body.get("channel_ids", [])
    for ch_id in channel_ids:
        db.add(AlertRuleNotification(rule_id=rule.id, channel_id=ch_id))
    if channel_ids:
        await db.commit()

    return JSONResponse({
        "success": True,
        "message": f"Rule '{name}' created",
        "rule_id": rule.id,
    }, status_code=201)


@router.put("/api/alert-rules/{rule_id}", name="api_update_alert_rule",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_update_alert_rule(rule_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update an alert rule."""
    body = await request.json()

    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse({"success": False, "error": "Rule not found"}, status_code=404)

    for field in ["name", "description", "severity", "category", "is_enabled",
                  "condition_type", "condition_config", "cooldown_minutes",
                  "mitre_tactic", "mitre_technique"]:
        if field in body:
            setattr(rule, field, body[field])

    # Update notification channels if provided
    if "channel_ids" in body:
        # Remove existing mappings
        existing = await db.execute(
            select(AlertRuleNotification).where(AlertRuleNotification.rule_id == rule_id)
        )
        for m in existing.scalars().all():
            await db.delete(m)

        # Add new ones
        for ch_id in body["channel_ids"]:
            db.add(AlertRuleNotification(rule_id=rule_id, channel_id=ch_id))

    await db.commit()

    return JSONResponse({"success": True, "message": f"Rule '{rule.name}' updated"})


@router.delete("/api/alert-rules/{rule_id}", name="api_delete_alert_rule",
               dependencies=[Depends(require_min_role("ANALYST"))])
async def api_delete_alert_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an alert rule."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse({"success": False, "error": "Rule not found"}, status_code=404)

    name = rule.name
    await db.delete(rule)
    await db.commit()

    return JSONResponse({"success": True, "message": f"Rule '{name}' deleted"})


@router.post("/api/alert-rules/{rule_id}/toggle", name="api_toggle_alert_rule",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_toggle_alert_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Enable/disable an alert rule."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        return JSONResponse({"success": False, "error": "Rule not found"}, status_code=404)

    rule.is_enabled = not rule.is_enabled
    await db.commit()

    status = "enabled" if rule.is_enabled else "disabled"
    return JSONResponse({"success": True, "message": f"Rule '{rule.name}' {status}", "is_enabled": rule.is_enabled})


@router.post("/api/alert-rules/{rule_id}/test", name="api_test_alert_rule",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_test_alert_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Dry-run test an alert rule against last hour of data."""
    from ..services.alert_engine import test_rule_dry_run

    result = await test_rule_dry_run(rule_id)
    return JSONResponse(result)


# ============================================================
# Notification Channels API
# ============================================================

@router.get("/alerts/channels/", response_class=HTMLResponse, name="notification_channels_page",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def notification_channels_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Notification channels management page."""
    result = await db.execute(select(NotificationChannel).order_by(NotificationChannel.created_at.desc()))
    channels = result.scalars().all()

    return _render("alerts/notification_channels.html", request, {
        "channels": channels,
    })


@router.get("/api/notification-channels/", name="api_channel_list",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_channel_list(db: AsyncSession = Depends(get_db)):
    """List notification channels."""
    result = await db.execute(select(NotificationChannel).order_by(NotificationChannel.name))
    channels = result.scalars().all()

    return JSONResponse({
        "success": True,
        "channels": [
            {
                "id": c.id,
                "name": c.name,
                "channel_type": c.channel_type,
                "config": c.config,
                "is_enabled": c.is_enabled,
                "last_sent_at": c.last_sent_at.isoformat() if c.last_sent_at else None,
            }
            for c in channels
        ],
    })


@router.post("/api/notification-channels/", name="api_create_channel",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_create_channel(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a notification channel."""
    body = await request.json()

    name = body.get("name", "").strip()
    channel_type = body.get("channel_type", "")
    config = body.get("config", {})

    if not name or not channel_type:
        return JSONResponse({"success": False, "error": "Name and type are required"}, status_code=400)

    channel = NotificationChannel(
        name=name,
        channel_type=channel_type,
        config=config,
        is_enabled=body.get("is_enabled", True),
    )
    db.add(channel)
    await db.commit()
    await db.refresh(channel)

    return JSONResponse({"success": True, "message": f"Channel '{name}' created", "channel_id": channel.id}, status_code=201)


@router.put("/api/notification-channels/{channel_id}", name="api_update_channel",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_update_channel(channel_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update a notification channel."""
    body = await request.json()

    result = await db.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        return JSONResponse({"success": False, "error": "Channel not found"}, status_code=404)

    for field in ["name", "channel_type", "config", "is_enabled"]:
        if field in body:
            setattr(channel, field, body[field])

    await db.commit()

    return JSONResponse({"success": True, "message": f"Channel '{channel.name}' updated"})


@router.delete("/api/notification-channels/{channel_id}", name="api_delete_channel",
               dependencies=[Depends(require_min_role("ANALYST"))])
async def api_delete_channel(channel_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a notification channel."""
    result = await db.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        return JSONResponse({"success": False, "error": "Channel not found"}, status_code=404)

    name = channel.name
    await db.delete(channel)
    await db.commit()

    return JSONResponse({"success": True, "message": f"Channel '{name}' deleted"})


@router.post("/api/notification-channels/{channel_id}/test", name="api_test_channel",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_test_channel(channel_id: int, db: AsyncSession = Depends(get_db)):
    """Send a test notification through a channel."""
    from ..services.notification_service import send_test_notification

    result = await db.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        return JSONResponse({"success": False, "error": "Channel not found"}, status_code=404)

    test_result = await send_test_notification(channel)
    return JSONResponse(test_result)


# ============================================================
# Helper: Get unread alert count (for nav badge)
# ============================================================

async def get_unread_alert_count(db: AsyncSession) -> int:
    """Get count of unresolved critical/high alerts for nav badge."""
    result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity.in_(["critical", "high"]),
            Alert.status.in_(["new", "acknowledged", "investigating"]),
        )
    )
    return result.scalar() or 0
