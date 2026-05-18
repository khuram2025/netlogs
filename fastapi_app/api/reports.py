"""
Reports module — branded, print-optimized HTML reports.

Each report is a server-rendered HTML page that fetches data via existing
analytics APIs on the client side; the page includes print-optimized CSS so
"Download PDF" simply triggers window.print() to save a polished PDF.

Routes:
- GET /reports/                      → reports index
- GET /reports/executive             → executive summary report
- GET /reports/user-activity         → per-user detailed activity report
- GET /reports/productivity          → productivity report (org-wide)
- GET /reports/security              → security/blocked/threats report
- GET /reports/bandwidth             → bandwidth consumption report
- GET /reports/top-users             → top users by activity report

Fast per-user API:
- GET /api/reports/user-activity?user=X&hours=N
    Single-pass query against url_logs (much smaller than syslogs) returning
    summary + categories + hostnames + actions + productivity + bandwidth.
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

router = APIRouter(tags=["reports"])
templates = Jinja2Templates(directory="fastapi_app/templates")


# Productivity classification (mirrors url_dashboard so reports stay consistent)
_PROD = {
    "productive": {
        "business", "information technology", "internet services", "education",
        "computer and internet info", "government", "finance and banking",
        "health and medicine", "news", "reference and research", "search engines",
        "training-and-tools", "online-storage-and-backup",
    },
    "neutral": {
        "search engines and portals", "general", "uncategorized", "unrated",
        "translation", "weather", "real-estate", "shopping", "society",
    },
    "unproductive": {
        "social networking", "entertainment", "streaming media", "games",
        "online communities", "sports", "personal sites and blogs", "shopping",
        "social-media", "music",
    },
    "risky": {
        "adult", "gambling", "weapons", "violence", "drugs", "alcohol-and-tobacco",
        "malware", "phishing", "command-and-control", "proxy avoidance and anonymizers",
        "spam", "hacking",
    },
}

def _classify(cat: str) -> str:
    c = (cat or "").lower().strip()
    if not c:
        return "neutral"
    for cls, names in _PROD.items():
        if c in names:
            return cls
    return "neutral"


def _safe(v, d=0):
    if v is None:
        return d
    try:
        import math
        if isinstance(v, float) and math.isnan(v):
            return d
    except Exception:
        pass
    return v


BLOCKED_ACTIONS = ('blocked', 'block-url', 'deny', 'drop', 'reset-client', 'reset-server')


def _base_context(request: Request) -> dict:
    ctx = {"request": request, "app_version": __version__}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = getattr(request.state, "_alert_count", 0)
    return ctx


@router.get("/reports/", response_class=HTMLResponse, name="reports_index",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def reports_index(request: Request):
    return templates.TemplateResponse("reports/index.html", _base_context(request))


@router.get("/reports/executive", response_class=HTMLResponse, name="report_executive",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_executive(request: Request, hours: int = Query(24, ge=1, le=720)):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    return templates.TemplateResponse("reports/executive.html", ctx)


@router.get("/reports/user-activity", response_class=HTMLResponse, name="report_user_activity",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_user_activity(
    request: Request,
    user: Optional[str] = Query(None, description="Username or IP"),
    hours: int = Query(24, ge=1, le=720),
):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    ctx["report_user"] = user or ""
    return templates.TemplateResponse("reports/user_activity.html", ctx)


@router.get("/reports/productivity", response_class=HTMLResponse, name="report_productivity",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_productivity(request: Request, hours: int = Query(24, ge=1, le=720)):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    return templates.TemplateResponse("reports/productivity.html", ctx)


@router.get("/reports/security", response_class=HTMLResponse, name="report_security",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_security(request: Request, hours: int = Query(24, ge=1, le=720)):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    return templates.TemplateResponse("reports/security.html", ctx)


@router.get("/reports/bandwidth", response_class=HTMLResponse, name="report_bandwidth",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_bandwidth(request: Request, hours: int = Query(24, ge=1, le=720)):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    return templates.TemplateResponse("reports/bandwidth.html", ctx)


@router.get("/reports/top-users", response_class=HTMLResponse, name="report_top_users",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def report_top_users(request: Request, hours: int = Query(24, ge=1, le=720)):
    ctx = _base_context(request)
    ctx["report_hours"] = hours
    return templates.TemplateResponse("reports/top_users.html", ctx)


# ============================================================
# Fast per-user analytics — queries url_logs (not raw syslogs)
# ============================================================

@router.get("/api/reports/user-activity",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_report_user_activity(
    user: str = Query(..., description="Username or IP"),
    hours: int = Query(24, ge=1, le=720),
):
    """Single-pass per-user analytics against the aggregated url_logs table.

    Filters by `src_user = :u` when the value looks like a username, otherwise
    by `src_ip = :u`. Returns summary, top categories, top hostnames, actions,
    productivity, first/last seen, and bandwidth — all in parallel queries.
    """
    try:
        import re
        client = ClickHouseClient.get_client()
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', user))
        if is_ip:
            uf = "src_ip = {u:String}"
        else:
            uf = "src_user = {u:String}"
        params = {"u": user}
        time_clause = f"timestamp > now() - INTERVAL {hours} HOUR AND {uf}"

        # NOTE on session-update inflation:
        # Fortinet emits multiple "session update" rows per session with
        # cumulative byte counts. Summing `sent_bytes` directly over-counts
        # by 100×–1000×. We dedupe per session_id and take max (cumulative
        # is monotonic, so max == final).

        # ── summary (counts from raw rows; bandwidth from per-session max)
        sum_q = f"""
        SELECT
            count() AS total,
            countIf(action IN {BLOCKED_ACTIONS}) AS blocked,
            count() - countIf(action IN {BLOCKED_ACTIONS}) AS allowed,
            countIf(action = 'alert') AS alerted,
            uniqExact(hostname) AS sites,
            uniqExact(url_category) AS categories,
            min(timestamp) AS first_seen,
            max(timestamp) AS last_seen,
            any(src_user) AS sample_user,
            any(src_ip) AS sample_ip
        FROM url_logs WHERE {time_clause}
        """
        s_rows = list(client.query(sum_q, parameters=params).named_results())
        s = s_rows[0] if s_rows else {}

        bw_q = f"""
        SELECT sum(s) AS sent, sum(r) AS recv, sum(s + r) AS bw
        FROM (
            SELECT session_id, max(sent_bytes) AS s, max(recv_bytes) AS r
            FROM url_logs
            WHERE {time_clause}
            GROUP BY session_id
        )
        """
        bw_rows = list(client.query(bw_q, parameters=params).named_results())
        bw = bw_rows[0] if bw_rows else {}

        # ── top categories (sum requests across rows; sum dedup'd bandwidth across sessions)
        cat_q = f"""
        SELECT category, sum(req_cnt) AS requests, sum(bw_max) AS bandwidth,
               sum(blk_cnt) AS blocked
        FROM (
            SELECT
                url_category AS category, session_id,
                count() AS req_cnt,
                countIf(action IN {BLOCKED_ACTIONS}) AS blk_cnt,
                max(sent_bytes + recv_bytes) AS bw_max
            FROM url_logs
            WHERE {time_clause} AND url_category != ''
            GROUP BY url_category, session_id
        )
        GROUP BY category ORDER BY requests DESC LIMIT 12
        """
        cats = []
        productivity = {"productive": 0, "neutral": 0, "unproductive": 0, "risky": 0}
        for r in client.query(cat_q, parameters=params).named_results():
            cls = _classify(r["category"])
            productivity[cls] += _safe(r["requests"])
            cats.append({
                "category": r["category"],
                "requests": _safe(r["requests"]),
                "bandwidth": _safe(r["bandwidth"]),
                "blocked": _safe(r["blocked"]),
                "productivity": cls,
            })

        # ── top hostnames (same approach: row counts from raw, bw via session dedup)
        host_q = f"""
        SELECT hostname, sum(req_cnt) AS requests, sum(bw_max) AS bandwidth,
               any(category) AS category,
               sum(blk_cnt) AS blocked
        FROM (
            SELECT
                hostname, session_id,
                count() AS req_cnt,
                countIf(action IN {BLOCKED_ACTIONS}) AS blk_cnt,
                any(url_category) AS category,
                max(sent_bytes + recv_bytes) AS bw_max
            FROM url_logs
            WHERE {time_clause} AND hostname != ''
            GROUP BY hostname, session_id
        )
        GROUP BY hostname ORDER BY requests DESC LIMIT 15
        """
        hosts = [{"hostname": r["hostname"], "requests": _safe(r["requests"]),
                  "bandwidth": _safe(r["bandwidth"]),
                  "category": r["category"] or "",
                  "blocked": _safe(r["blocked"])}
                 for r in client.query(host_q, parameters=params).named_results()]

        # ── actions breakdown
        act_q = f"""
        SELECT action, count() AS cnt FROM url_logs
        WHERE {time_clause} AND action != ''
        GROUP BY action ORDER BY cnt DESC
        """
        actions = [{"action": r["action"], "count": _safe(r["cnt"])}
                   for r in client.query(act_q, parameters=params).named_results()]

        # ── top blocked hosts (for security section)
        blk_q = f"""
        SELECT hostname, count() AS blocked_count, any(url_category) AS category
        FROM url_logs WHERE {time_clause} AND action IN {BLOCKED_ACTIONS} AND hostname != ''
        GROUP BY hostname ORDER BY blocked_count DESC LIMIT 10
        """
        blocked_hosts = [{"hostname": r["hostname"], "blocked_count": _safe(r["blocked_count"]),
                          "category": r["category"] or ""}
                         for r in client.query(blk_q, parameters=params).named_results()]

        total = _safe(s.get("total"))
        blocked = _safe(s.get("blocked"))
        return JSONResponse({
            "success": True,
            "user": user,
            "hours": hours,
            "summary": {
                "total_events": total,
                "allowed": _safe(s.get("allowed")),
                "blocked": blocked,
                "alerted": _safe(s.get("alerted")),
                "block_rate": round(blocked / total * 100, 2) if total else 0,
                "unique_sites": _safe(s.get("sites")),
                "unique_categories": _safe(s.get("categories")),
                "bytes_sent": _safe(bw.get("sent")),
                "bytes_recv": _safe(bw.get("recv")),
                "total_bytes": _safe(bw.get("bw")),
                "first_seen": s.get("first_seen").isoformat() if s.get("first_seen") and hasattr(s["first_seen"], "isoformat") else "",
                "last_seen":  s.get("last_seen").isoformat()  if s.get("last_seen")  and hasattr(s["last_seen"],  "isoformat") else "",
                "username": s.get("sample_user") or "",
                "src_ip":   s.get("sample_ip") or "",
            },
            "productivity": productivity,
            "categories": cats,
            "hostnames": hosts,
            "actions": actions,
            "blocked_hosts": blocked_hosts,
        })
    except Exception as e:
        logger.error(f"User activity report error: {e}", exc_info=True)
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
