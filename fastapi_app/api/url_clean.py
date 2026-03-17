"""SiteClean — URL noise filtering rules CRUD API + management page."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func

from ..core.permissions import require_min_role
from ..db.database import async_session_maker
from ..db.clickhouse import ClickHouseClient
from ..models.url_clean import URLCleanRule
from ..services.siteclean import invalidate_cache, build_siteclean_match_where
from ..__version__ import __version__

logger = logging.getLogger(__name__)

router = APIRouter(tags=["url-clean"])
templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request, "app_version": __version__}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = getattr(request.state, "_alert_count", 0)
    return ctx


# ── Management Page ──────────────────────────────────────────────────

@router.get("/system/url-clean/", response_class=HTMLResponse, name="url_clean_page",
            dependencies=[Depends(require_min_role("ADMIN"))])
async def url_clean_page(request: Request):
    ctx = _base_context(request)
    return templates.TemplateResponse("system/url_clean.html", ctx)


# ── CRUD API ─────────────────────────────────────────────────────────

@router.get("/api/url-clean/rules", name="api_url_clean_rules",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def list_rules():
    """List all SiteClean rules."""
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(URLCleanRule).order_by(URLCleanRule.group_name, URLCleanRule.label)
            )
            rules = result.scalars().all()
            return JSONResponse({
                "success": True,
                "rules": [
                    {
                        "id": r.id,
                        "rule_type": r.rule_type,
                        "pattern": r.pattern,
                        "label": r.label,
                        "group_name": r.group_name,
                        "enabled": r.enabled,
                        "is_builtin": r.is_builtin,
                    }
                    for r in rules
                ],
            })
    except Exception as e:
        logger.error(f"List rules error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/url-clean/rules", name="api_url_clean_create",
             dependencies=[Depends(require_min_role("ADMIN"))])
async def create_rule(request: Request):
    """Create a custom SiteClean rule."""
    try:
        body = await request.json()
        rule_type = body.get("rule_type", "")
        pattern = body.get("pattern", "").strip()
        label = body.get("label", "").strip()
        group_name = body.get("group_name", "Custom").strip()

        if rule_type not in ("hostname_exact", "hostname_glob", "category", "url_contains"):
            return JSONResponse({"success": False, "error": "Invalid rule_type"}, status_code=400)
        if not pattern or not label:
            return JSONResponse({"success": False, "error": "Pattern and label are required"}, status_code=400)
        if "'" in pattern or ";" in pattern or "--" in pattern:
            return JSONResponse({"success": False, "error": "Pattern contains invalid characters"}, status_code=400)

        async with async_session_maker() as session:
            rule = URLCleanRule(
                rule_type=rule_type,
                pattern=pattern,
                label=label,
                group_name=group_name or "Custom",
                enabled=True,
                is_builtin=False,
            )
            session.add(rule)
            await session.commit()
            await session.refresh(rule)
            invalidate_cache()

            return JSONResponse({
                "success": True,
                "rule": {"id": rule.id, "label": rule.label, "pattern": rule.pattern},
            })
    except Exception as e:
        logger.error(f"Create rule error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.put("/api/url-clean/rules/{rule_id}", name="api_url_clean_update",
            dependencies=[Depends(require_min_role("ADMIN"))])
async def update_rule(rule_id: int, request: Request):
    """Update a SiteClean rule (toggle enabled, edit pattern/label)."""
    try:
        body = await request.json()
        async with async_session_maker() as session:
            result = await session.execute(
                select(URLCleanRule).where(URLCleanRule.id == rule_id)
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return JSONResponse({"success": False, "error": "Rule not found"}, status_code=404)

            if "enabled" in body:
                rule.enabled = bool(body["enabled"])
            # For builtin rules, only allow toggling enabled
            if not rule.is_builtin:
                if "pattern" in body:
                    p = body["pattern"].strip()
                    if "'" in p or ";" in p or "--" in p:
                        return JSONResponse({"success": False, "error": "Invalid characters"}, status_code=400)
                    rule.pattern = p
                if "label" in body:
                    rule.label = body["label"].strip()
                if "group_name" in body:
                    rule.group_name = body["group_name"].strip()
                if "rule_type" in body:
                    rule.rule_type = body["rule_type"]

            await session.commit()
            invalidate_cache()
            return JSONResponse({"success": True})
    except Exception as e:
        logger.error(f"Update rule error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.delete("/api/url-clean/rules/{rule_id}", name="api_url_clean_delete",
               dependencies=[Depends(require_min_role("ADMIN"))])
async def delete_rule(rule_id: int):
    """Delete a custom SiteClean rule. Builtin rules cannot be deleted."""
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(URLCleanRule).where(URLCleanRule.id == rule_id)
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return JSONResponse({"success": False, "error": "Not found"}, status_code=404)
            if rule.is_builtin:
                return JSONResponse({"success": False, "error": "Cannot delete builtin rules. Disable instead."}, status_code=403)

            await session.delete(rule)
            await session.commit()
            invalidate_cache()
            return JSONResponse({"success": True})
    except Exception as e:
        logger.error(f"Delete rule error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/url-clean/rules/toggle-all", name="api_url_clean_toggle_all",
             dependencies=[Depends(require_min_role("ADMIN"))])
async def toggle_all_rules(request: Request):
    """Bulk enable/disable all rules."""
    try:
        body = await request.json()
        enabled = bool(body.get("enabled", True))
        async with async_session_maker() as session:
            result = await session.execute(select(URLCleanRule))
            for rule in result.scalars().all():
                rule.enabled = enabled
            await session.commit()
            invalidate_cache()
            return JSONResponse({"success": True, "enabled": enabled})
    except Exception as e:
        logger.error(f"Toggle all error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ── Noise Count Endpoint ─────────────────────────────────────────────

@router.get("/api/threats/url-logs/noise-count", name="api_url_noise_count",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_url_noise_count(hours: int = Query(24, ge=1, le=720)):
    """Count of URL logs that match SiteClean noise rules."""
    try:
        match_clause = await build_siteclean_match_where()
        if not match_clause:
            return JSONResponse({"success": True, "noise_count": 0, "total_count": 0})

        client = ClickHouseClient.get_client()
        tw = f"timestamp > now() - INTERVAL {hours} HOUR"

        noise_q = f"SELECT count() FROM url_logs WHERE {tw} {match_clause}"
        total_q = f"SELECT count() FROM url_logs WHERE {tw}"

        noise = (client.query(noise_q).result_rows or [[0]])[0][0]
        total = (client.query(total_q).result_rows or [[0]])[0][0]

        return JSONResponse({
            "success": True,
            "noise_count": noise,
            "total_count": total,
            "clean_count": total - noise,
            "noise_pct": round(noise / total * 100, 1) if total else 0,
        })
    except Exception as e:
        logger.error(f"Noise count error: {e}")
        return JSONResponse({"success": True, "noise_count": 0, "total_count": 0})


@router.get("/api/url-clean/preview", name="api_url_clean_preview",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def preview_rules(hours: int = Query(1, ge=1, le=24)):
    """Preview: how many logs each active rule matches."""
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(URLCleanRule).where(URLCleanRule.enabled.is_(True))
                .order_by(URLCleanRule.group_name, URLCleanRule.label)
            )
            rules = result.scalars().all()

        if not rules:
            return JSONResponse({"success": True, "rules": [], "total_noise": 0})

        client = ClickHouseClient.get_client()
        tw = f"timestamp > now() - INTERVAL {hours} HOUR"
        from ..services.siteclean import _safe_pattern

        preview = []
        for r in rules:
            safe = _safe_pattern(r.pattern)
            if r.rule_type == "hostname_exact":
                cond = f"hostname = '{safe}'"
            elif r.rule_type == "hostname_glob":
                like = safe.replace("*", "%").replace("?", "_")
                cond = f"hostname LIKE '{like}'"
            elif r.rule_type == "category":
                cond = f"url_category = '{safe}'"
            elif r.rule_type == "url_contains":
                cond = f"url LIKE '%{safe}%'"
            else:
                continue

            q = f"SELECT count() FROM url_logs WHERE {tw} AND {cond}"
            try:
                cnt = (client.query(q).result_rows or [[0]])[0][0]
            except Exception:
                cnt = 0

            preview.append({
                "id": r.id,
                "label": r.label,
                "group_name": r.group_name,
                "rule_type": r.rule_type,
                "pattern": r.pattern,
                "match_count": cnt,
            })

        total_noise = sum(p["match_count"] for p in preview)
        return JSONResponse({"success": True, "rules": preview, "total_noise": total_noise})
    except Exception as e:
        logger.error(f"Preview error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
