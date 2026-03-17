"""
Per-User Activity Timeline — user list + individual activity views.

Queries syslogs (traffic) and pa_threat_logs + Fortinet UTM (URL/DNS)
to build a unified per-user activity view.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..core.permissions import require_min_role
from ..db.clickhouse import ClickHouseClient
from ..__version__ import __version__

logger = logging.getLogger(__name__)

router = APIRouter(tags=["user-activity"])
templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request, "app_version": __version__}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = getattr(request.state, "_alert_count", 0)
    return ctx


def _safe(val, default=0):
    if val is None:
        return default
    try:
        import math
        if isinstance(val, float) and math.isnan(val):
            return default
    except Exception:
        pass
    return val


# ============================================================
# Pages
# ============================================================

@router.get("/users/activity/", response_class=HTMLResponse, name="user_activity_list",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def user_activity_list_page(request: Request):
    """User activity list — shows top active users."""
    ctx = _base_context(request)
    return templates.TemplateResponse("user_activity/user_list.html", ctx)


@router.get("/users/activity/timeline", response_class=HTMLResponse, name="user_activity_timeline",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def user_activity_timeline_page(request: Request):
    """Per-user activity timeline page."""
    ctx = _base_context(request)
    return templates.TemplateResponse("user_activity/timeline.html", ctx)


# ============================================================
# JSON API — Top Users (aggregated from syslogs)
# ============================================================

@router.get("/api/users/activity/top", name="api_user_activity_top",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_user_activity_top(
    hours: int = Query(24, ge=1, le=720),
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Top active users by event count — groups by srcip."""
    try:
        client = ClickHouseClient.get_client()

        search_clause = ""
        params = {}
        if search:
            search_clause = "AND (toString(srcip) ILIKE {q:String} OR parsed_data['user'] ILIKE {q:String} OR parsed_data['srcuser'] ILIKE {q:String})"
            params["q"] = f"%{search}%"

        # Ultra-fast query — count + countIf only, no uniq (avoids hash tables on 80M+ rows)
        query = f"""
        SELECT
            srcip as user_ip,
            count() as event_count,
            countIf(action IN ('deny', 'drop', 'block', 'reject', 'block-url', 'reset-client')) as denied_count,
            max(timestamp) as last_seen,
            countIf(log_type IN ('utm/webfilter', 'utm/dns', 'utm/virus', 'utm/ips', 'threat')) as threat_events
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          AND srcip != ''
          {search_clause}
        GROUP BY srcip
        ORDER BY event_count DESC
        LIMIT {limit} OFFSET {offset}
        """
        rows = list(client.query(query, parameters=params).named_results())

        total = len(rows)  # approximate — we got up to LIMIT rows

        users = []
        for r in rows:
            ls = r.get('last_seen')
            uip = str(r['user_ip'])
            users.append({
                "user_id": uip,
                "primary_ip": uip,
                "event_count": _safe(r['event_count']),
                "denied_count": _safe(r['denied_count']),
                "threat_events": _safe(r['threat_events']),
                "last_seen": ls.isoformat() if hasattr(ls, 'isoformat') else str(ls) if ls else "",
            })

        return JSONResponse({
            "success": True, "total": total,
            "limit": limit, "offset": offset, "users": users,
        })
    except Exception as e:
        logger.error(f"User activity top error: {e}")
        return JSONResponse({"success": True, "total": 0, "users": []})


# ============================================================
# JSON API — Per-User Activity Summary
# ============================================================

@router.get("/api/users/activity/summary", name="api_user_activity_summary",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_user_activity_summary(
    user: str = Query(..., description="Username or IP address"),
    hours: int = Query(24, ge=1, le=720),
):
    """Summary stats for a specific user — KPIs, top destinations, apps, categories."""
    try:
        client = ClickHouseClient.get_client()

        # Fast path: if user looks like an IP, filter by srcip only (indexed).
        # Otherwise fall back to OR-based lookup on parsed_data.
        import re
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', user))
        if is_ip:
            user_filter = " AND srcip = {u:String}"
        else:
            user_filter = " AND (parsed_data['user'] = {u:String} OR parsed_data['srcuser'] = {u:String})"
        params = {"u": user}

        # === Single-pass summary — only indexed/LowCardinality columns ===
        summary_q = f"""
        SELECT
            count() as total_events,
            uniq(dstip) as unique_destinations,
            uniq(dstport) as unique_ports,
            uniq(application) as unique_apps,
            countIf(action IN ('deny','drop','block','reject','block-url','reset-client')) as denied,
            countIf(action IN ('accept','allow','pass','passthrough')) as allowed,
            countIf(log_type IN ('utm/webfilter','utm/dns','utm/virus','utm/ips','threat')) as threat_events,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter}
        """
        sr = list(client.query(summary_q, parameters=params).named_results())
        s = sr[0] if sr else {}

        summary = {
            "total_events": _safe(s.get('total_events')),
            "unique_destinations": _safe(s.get('unique_destinations')),
            "unique_ports": _safe(s.get('unique_ports')),
            "unique_apps": _safe(s.get('unique_apps')),
            "bytes_sent": 0, "bytes_recv": 0, "total_bytes": 0,
            "denied": _safe(s.get('denied')),
            "allowed": _safe(s.get('allowed')),
            "threat_events": _safe(s.get('threat_events')),
            "first_seen": s['first_seen'].isoformat() if s.get('first_seen') and hasattr(s['first_seen'], 'isoformat') else "",
            "last_seen": s['last_seen'].isoformat() if s.get('last_seen') and hasattr(s['last_seen'], 'isoformat') else "",
            "all_ips": [user] if is_ip else [],
        }

        # === Top destinations (indexed columns only) ===
        dest_q = f"""
        SELECT dstip, count() as cnt
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter} AND dstip != ''
        GROUP BY dstip ORDER BY cnt DESC LIMIT 10
        """
        dests = [{"ip": str(r['dstip']), "count": _safe(r['cnt']), "bytes": 0}
                 for r in client.query(dest_q, parameters=params).named_results()]

        # === Top applications ===
        app_q = f"""
        SELECT application, count() as cnt
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter} AND application != ''
        GROUP BY application ORDER BY cnt DESC LIMIT 10
        """
        apps = [{"application": r['application'], "count": _safe(r['cnt']), "bytes": 0}
                for r in client.query(app_q, parameters=params).named_results()]

        # === Action breakdown ===
        act_q = f"""
        SELECT action, count() as cnt
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter}
        GROUP BY action ORDER BY cnt DESC
        """
        actions = [{"action": r['action'], "count": _safe(r['cnt'])}
                   for r in client.query(act_q, parameters=params).named_results()]

        # === Top URL categories (only UTM subset — much smaller scan) ===
        cat_q = f"""
        SELECT
            coalesce(nullIf(parsed_data['catdesc'],''), parsed_data['urlcat'], '') as category,
            count() as cnt
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter}
          AND log_type IN ('utm/webfilter', 'threat')
          AND coalesce(nullIf(parsed_data['catdesc'],''), parsed_data['urlcat'], '') != ''
        GROUP BY category ORDER BY cnt DESC LIMIT 10
        """
        categories = [{"category": r['category'], "count": _safe(r['cnt'])}
                      for r in client.query(cat_q, parameters=params).named_results()]

        # === Top URLs visited (only UTM subset) ===
        url_q = f"""
        SELECT
            coalesce(nullIf(parsed_data['url'],''), parsed_data['hostname'], '') as url,
            count() as cnt
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter}
          AND log_type IN ('utm/webfilter', 'threat')
          AND coalesce(nullIf(parsed_data['url'],''), parsed_data['hostname'], '') != ''
        GROUP BY url ORDER BY cnt DESC LIMIT 15
        """
        urls = [{"url": r['url'], "count": _safe(r['cnt'])}
                for r in client.query(url_q, parameters=params).named_results()]

        ports = []
        timeline = []

        return JSONResponse({
            "success": True, "user": user, "hours": hours,
            "summary": summary,
            "top_destinations": dests,
            "top_applications": apps,
            "top_ports": ports,
            "actions": actions,
            "top_categories": categories,
            "top_urls": urls,
            "timeline": timeline,
        })
    except Exception as e:
        logger.error(f"User activity summary error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# JSON API — Per-User Event Log (paginated)
# ============================================================

@router.get("/api/users/activity/events", name="api_user_activity_events",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_user_activity_events(
    user: str = Query(..., description="Username or IP address"),
    hours: int = Query(24, ge=1, le=720),
    log_type: Optional[str] = None,
    action: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated event log for a specific user."""
    try:
        client = ClickHouseClient.get_client()

        import re
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', user))
        if is_ip:
            user_filter = " AND srcip = {u:String}"
        else:
            user_filter = " AND (parsed_data['user'] = {u:String} OR parsed_data['srcuser'] = {u:String})"
        params = {"u": user}
        extra = ""

        if log_type:
            extra += " AND log_type = {lt:String}"
            params["lt"] = log_type
        if action:
            extra += " AND action = {act:String}"
            params["act"] = action
        if search:
            extra += """ AND (
                message ILIKE {q:String}
                OR dstip ILIKE {q:String}
                OR application ILIKE {q:String}
                OR parsed_data['url'] ILIKE {q:String}
                OR parsed_data['hostname'] ILIKE {q:String}
            )"""
            params["q"] = f"%{search}%"

        # Count
        count_q = f"""
        SELECT count()
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter} {extra}
        """
        total = _safe((client.query(count_q, parameters=params).result_rows or [[0]])[0][0])

        # Events
        query = f"""
        SELECT
            timestamp,
            srcip,
            dstip,
            srcport,
            dstport,
            action,
            log_type,
            application,
            policyname,
            device_ip,
            coalesce(nullIf(parsed_data['user'],''), parsed_data['srcuser'], '') as src_user,
            coalesce(nullIf(parsed_data['url'],''), parsed_data['hostname'], '') as url,
            coalesce(nullIf(parsed_data['catdesc'],''), parsed_data['urlcat'], '') as category,
            parsed_data['sentbyte'] as sent,
            parsed_data['rcvdbyte'] as recv,
            proto,
            src_zone,
            dst_zone,
            coalesce(nullIf(parsed_data['virus'],''), nullIf(parsed_data['attack'],''),
                     nullIf(parsed_data['msg'],''), '') as threat_name
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {user_filter} {extra}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """
        rows = list(client.query(query, parameters=params).named_results())
        events = []
        for r in rows:
            ts = r['timestamp']
            sent = int(r.get('sent') or 0) if r.get('sent') else 0
            recv = int(r.get('recv') or 0) if r.get('recv') else 0
            proto_num = r.get('proto', 0)
            proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
            events.append({
                "timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                "src_ip": str(r['srcip']),
                "dest_ip": str(r['dstip']),
                "src_port": r['srcport'],
                "dest_port": r['dstport'],
                "action": r['action'],
                "log_type": r['log_type'],
                "application": r['application'],
                "policy": r['policyname'],
                "device_ip": str(r['device_ip']),
                "src_user": r['src_user'],
                "url": r['url'],
                "category": r['category'],
                "bytes_sent": sent,
                "bytes_recv": recv,
                "total_bytes": sent + recv,
                "protocol": proto_map.get(proto_num, str(proto_num)),
                "src_zone": r['src_zone'],
                "dest_zone": r['dst_zone'],
                "threat_name": r['threat_name'],
            })

        return JSONResponse({
            "success": True, "total": total,
            "limit": limit, "offset": offset, "events": events,
        })
    except Exception as e:
        logger.error(f"User activity events error: {e}")
        return JSONResponse({"success": True, "total": 0, "events": []})
