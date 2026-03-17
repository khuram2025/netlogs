"""URL Analytics Dashboard — Web Activity Intelligence.

Provides deep analytics on URL/web browsing activity from the unified
url_logs ClickHouse table.  SiteClean filtering on by default.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..core.permissions import require_min_role
from ..db.clickhouse import ClickHouseClient
from ..services.siteclean import build_siteclean_where
from ..__version__ import __version__

logger = logging.getLogger(__name__)

router = APIRouter(tags=["url-analytics"])
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


# ── Productivity Classification ──────────────────────────────────────

PRODUCTIVITY_MAP = {
    # PRODUCTIVE
    "business": "productive", "finance-and-banking": "productive",
    "finance and banking": "productive", "education": "productive",
    "health-and-wellness": "productive", "health and wellness": "productive",
    "government": "productive", "legal": "productive",
    "web-based-email": "productive", "web-based email": "productive",
    "cloud-applications": "productive", "secure websites": "productive",
    "medicine": "productive",

    # NEUTRAL
    "search-engines-and-portals": "neutral", "search engines and portals": "neutral",
    "reference": "neutral", "news-and-media": "neutral", "news and media": "neutral",
    "general-interest": "neutral", "general interest - personal": "neutral",
    "information-technology": "neutral", "information technology": "neutral",
    "information and computer security": "neutral",
    "information and computer s...": "neutral",
    "content-servers": "neutral", "content servers": "neutral",
    "content-delivery-networks": "neutral",
    "web-hosting": "neutral", "web hosting": "neutral",
    "web-analytics": "neutral", "dynamic-content": "neutral",
    "shopping": "neutral", "real-estate": "neutral", "travel": "neutral",
    "restaurants-and-dining": "neutral", "restaurant and dining": "neutral",
    "sports": "neutral", "society-and-lifestyles": "neutral",
    "personal-vehicles": "neutral", "meaningless-content": "neutral",
    "computer-and-internet-info": "neutral", "computer-and-internet-i...": "neutral",
    "tm_service_gateway": "neutral", "allow": "neutral",

    # UNPRODUCTIVE
    "social-networking": "unproductive", "social networking": "unproductive",
    "streaming-media-and-download": "unproductive", "streaming media and download": "unproductive",
    "internet-radio-and-tv": "unproductive", "internet radio and tv": "unproductive",
    "games": "unproductive", "gambling": "unproductive",
    "dating": "unproductive", "peer-to-peer": "unproductive",
    "file-sharing-and-storage": "unproductive", "file sharing and storage": "unproductive",
    "personal-sites-and-blogs": "unproductive",
    "instant-messaging": "unproductive", "auction": "unproductive",
    "entertainment": "unproductive", "web-based-applications": "unproductive",
    "web-based applications": "unproductive",
    "freeware-and-software-downloads": "unproductive",
    "freeware and software downloads": "unproductive",
    "freeware and software dow...": "unproductive",

    # RISKY
    "malicious-websites": "risky", "malicious websites": "risky",
    "phishing": "risky", "spam-urls": "risky", "spam urls": "risky",
    "hacking": "risky", "proxy-avoidance": "risky",
    "potentially-unwanted-programs": "risky",
    "adult-and-pornography": "risky", "nudity-and-risque": "risky",
    "drug-abuse": "risky", "marijuana": "risky",
    "alcohol-and-tobacco": "risky", "weapons": "risky",
    "violence": "risky", "extremism": "risky", "terrorism": "risky",
    "child-abuse": "risky", "newly-observed-domain": "risky",
    "newly-registered-domain": "risky", "advertising": "risky",
    "medium-risk": "risky",
}


def classify_category(cat: str) -> str:
    if not cat:
        return "neutral"
    return PRODUCTIVITY_MAP.get(cat.lower().strip(), "neutral")


BLOCKED_ACTIONS = "('block-url','blocked','deny','drop','reset-client','reset-server')"


async def _sc_where() -> str:
    """Get SiteClean WHERE clause."""
    return await build_siteclean_where() or ""


# ── Page Route ───────────────────────────────────────────────────────

@router.get("/dashboards/url-analytics/", response_class=HTMLResponse,
            name="url_analytics_dashboard",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def url_analytics_page(request: Request):
    ctx = _base_context(request)
    return templates.TemplateResponse("dashboards/url_analytics.html", ctx)


# ── Summary Stats ────────────────────────────────────────────────────

@router.get("/api/url-analytics/summary",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_summary(hours: int = Query(24, ge=1, le=720)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT
            count() as total_requests,
            uniqExact(if(src_user != '', src_user, src_ip)) as unique_users,
            uniqExact(hostname) as unique_sites,
            sum(sent_bytes + recv_bytes) as total_bandwidth,
            sum(sent_bytes) as total_sent,
            sum(recv_bytes) as total_recv,
            countIf(action IN {BLOCKED_ACTIONS}) as blocked_count,
            uniqExact(url_category) as category_count,
            countIf(hostname LIKE '%youtube.com' OR hostname LIKE '%googlevideo.com') as youtube_requests
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR {sc}
        """
        rows = list(client.query(q).named_results())
        s = rows[0] if rows else {}
        return JSONResponse({"success": True, "summary": {
            "total_requests": _safe(s.get("total_requests")),
            "unique_users": _safe(s.get("unique_users")),
            "unique_sites": _safe(s.get("unique_sites")),
            "total_bandwidth": _safe(s.get("total_bandwidth")),
            "total_sent": _safe(s.get("total_sent")),
            "total_recv": _safe(s.get("total_recv")),
            "blocked_count": _safe(s.get("blocked_count")),
            "category_count": _safe(s.get("category_count")),
            "youtube_requests": _safe(s.get("youtube_requests")),
        }})
    except Exception as e:
        logger.error(f"Summary error: {e}")
        return JSONResponse({"success": True, "summary": {}})


# ── Top Categories ───────────────────────────────────────────────────

@router.get("/api/url-analytics/categories",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_categories(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=5, le=50)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT url_category, count() as requests,
               uniqExact(src_ip) as users,
               sum(sent_bytes + recv_bytes) as bandwidth,
               countIf(action IN {BLOCKED_ACTIONS}) as blocked
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND url_category != '' {sc}
        GROUP BY url_category ORDER BY requests DESC LIMIT {limit}
        """
        rows = list(client.query(q).named_results())
        cats = []
        productivity_summary = {"productive": 0, "neutral": 0, "unproductive": 0, "risky": 0}
        for r in rows:
            cat = r["url_category"]
            prod = classify_category(cat)
            productivity_summary[prod] += _safe(r["requests"])
            cats.append({
                "category": cat,
                "requests": _safe(r["requests"]),
                "users": _safe(r["users"]),
                "bandwidth": _safe(r["bandwidth"]),
                "blocked": _safe(r["blocked"]),
                "productivity": prod,
            })
        return JSONResponse({"success": True, "categories": cats, "productivity": productivity_summary})
    except Exception as e:
        logger.error(f"Categories error: {e}")
        return JSONResponse({"success": True, "categories": [], "productivity": {}})


# ── Top Hostnames ────────────────────────────────────────────────────

@router.get("/api/url-analytics/hostnames",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_hostnames(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=5, le=50)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT hostname, count() as requests,
               uniqExact(src_ip) as users,
               sum(sent_bytes + recv_bytes) as bandwidth,
               any(url_category) as category
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND hostname != '' {sc}
        GROUP BY hostname ORDER BY requests DESC LIMIT {limit}
        """
        rows = list(client.query(q).named_results())
        return JSONResponse({"success": True, "hostnames": [
            {"hostname": r["hostname"], "requests": _safe(r["requests"]),
             "users": _safe(r["users"]), "bandwidth": _safe(r["bandwidth"]),
             "category": r["category"] or ""}
            for r in rows
        ]})
    except Exception as e:
        logger.error(f"Hostnames error: {e}")
        return JSONResponse({"success": True, "hostnames": []})


# ── Top Users ────────────────────────────────────────────────────────

@router.get("/api/url-analytics/users",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_users(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=5, le=50)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT src_ip, any(src_user) as username,
               count() as requests,
               uniqExact(hostname) as unique_sites,
               sum(sent_bytes + recv_bytes) as bandwidth,
               countIf(action IN {BLOCKED_ACTIONS}) as blocked,
               topK(5)(hostname) as top_sites
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR {sc}
        GROUP BY src_ip ORDER BY requests DESC LIMIT {limit}
        """
        rows = list(client.query(q).named_results())
        return JSONResponse({"success": True, "users": [
            {"src_ip": r["src_ip"], "username": r["username"] or "",
             "requests": _safe(r["requests"]),
             "unique_sites": _safe(r["unique_sites"]),
             "bandwidth": _safe(r["bandwidth"]),
             "blocked": _safe(r["blocked"]),
             "top_sites": list(r.get("top_sites") or [])}
            for r in rows
        ]})
    except Exception as e:
        logger.error(f"Users error: {e}")
        return JSONResponse({"success": True, "users": []})


# ── YouTube / Video ──────────────────────────────────────────────────

@router.get("/api/url-analytics/youtube",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_youtube(hours: int = Query(24, ge=1, le=720)):
    try:
        client = ClickHouseClient.get_client()
        yt_filter = "(hostname LIKE '%youtube.com' OR hostname LIKE '%googlevideo.com' OR hostname LIKE '%ytimg.com')"

        # Totals
        tot_q = f"""
        SELECT count() as requests,
               uniqExact(src_ip) as users,
               sum(recv_bytes) as download_bytes,
               sum(sent_bytes + recv_bytes) as total_bandwidth
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {yt_filter}
        """
        tr = list(client.query(tot_q).named_results())
        t = tr[0] if tr else {}
        dl_bytes = _safe(t.get("download_bytes"))
        # Estimate: ~2.5 MB/min for 720p video
        est_minutes = round(dl_bytes / (2.5 * 1024 * 1024)) if dl_bytes else 0

        # Per-user
        usr_q = f"""
        SELECT src_ip, any(src_user) as username,
               count() as requests,
               sum(recv_bytes) as download_bytes,
               sum(sent_bytes + recv_bytes) as bandwidth
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {yt_filter}
        GROUP BY src_ip ORDER BY bandwidth DESC LIMIT 15
        """
        usr_rows = list(client.query(usr_q).named_results())
        users = []
        for r in usr_rows:
            dl = _safe(r["download_bytes"])
            users.append({
                "src_ip": r["src_ip"],
                "username": r["username"] or "",
                "requests": _safe(r["requests"]),
                "bandwidth": _safe(r["bandwidth"]),
                "download_bytes": dl,
                "est_minutes": round(dl / (2.5 * 1024 * 1024)) if dl else 0,
            })

        return JSONResponse({"success": True, "totals": {
            "requests": _safe(t.get("requests")),
            "users": _safe(t.get("users")),
            "download_bytes": dl_bytes,
            "total_bandwidth": _safe(t.get("total_bandwidth")),
            "est_watch_minutes": est_minutes,
            "est_watch_hours": round(est_minutes / 60, 1) if est_minutes else 0,
        }, "top_users": users})
    except Exception as e:
        logger.error(f"YouTube error: {e}")
        return JSONResponse({"success": True, "totals": {}, "top_users": []})


# ── Search Keywords ──────────────────────────────────────────────────

@router.get("/api/url-analytics/searches",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_searches(hours: int = Query(24, ge=1, le=720), limit: int = Query(30, ge=10, le=100)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT
            decodeURLComponent(extractURLParameter(url, 'q')) as query,
            count() as searches,
            uniqExact(src_ip) as users,
            any(src_user) as sample_user,
            any(hostname) as engine
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          AND (hostname LIKE '%google.%' OR hostname LIKE '%bing.com%'
               OR hostname LIKE '%duckduckgo.com%' OR hostname LIKE '%yahoo.com%')
          AND extractURLParameter(url, 'q') != ''
          {sc}
        GROUP BY query
        ORDER BY searches DESC
        LIMIT {limit}
        """
        rows = list(client.query(q).named_results())
        return JSONResponse({"success": True, "searches": [
            {"query": r["query"] or "", "searches": _safe(r["searches"]),
             "users": _safe(r["users"]), "user": r["sample_user"] or "",
             "engine": r["engine"] or ""}
            for r in rows
        ]})
    except Exception as e:
        logger.error(f"Searches error: {e}")
        return JSONResponse({"success": True, "searches": []})


# ── Blocked Sites ────────────────────────────────────────────────────

@router.get("/api/url-analytics/blocked",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_blocked(hours: int = Query(24, ge=1, le=720)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        blk = f"action IN {BLOCKED_ACTIONS}"

        # Top blocked hostnames
        host_q = f"""
        SELECT hostname, any(url_category) as category,
               count() as blocked_count,
               uniqExact(src_ip) as users_blocked
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {blk} AND hostname != '' {sc}
        GROUP BY hostname ORDER BY blocked_count DESC LIMIT 15
        """
        hosts = [{"hostname": r["hostname"], "category": r["category"] or "",
                  "blocked_count": _safe(r["blocked_count"]),
                  "users_blocked": _safe(r["users_blocked"])}
                 for r in client.query(host_q).named_results()]

        # Top blocked categories
        cat_q = f"""
        SELECT url_category, count() as cnt, uniqExact(src_ip) as users
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {blk} AND url_category != '' {sc}
        GROUP BY url_category ORDER BY cnt DESC LIMIT 10
        """
        cats = [{"category": r["url_category"], "count": _safe(r["cnt"]),
                 "users": _safe(r["users"])}
                for r in client.query(cat_q).named_results()]

        # Users hitting most blocks
        usr_q = f"""
        SELECT src_ip, any(src_user) as username, count() as blocked_count,
               uniqExact(hostname) as unique_blocked_sites
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {blk} {sc}
        GROUP BY src_ip ORDER BY blocked_count DESC LIMIT 10
        """
        users = [{"src_ip": r["src_ip"], "username": r["username"] or "",
                  "blocked_count": _safe(r["blocked_count"]),
                  "unique_blocked_sites": _safe(r["unique_blocked_sites"])}
                 for r in client.query(usr_q).named_results()]

        return JSONResponse({"success": True,
                             "blocked_hosts": hosts, "blocked_categories": cats,
                             "blocked_users": users})
    except Exception as e:
        logger.error(f"Blocked error: {e}")
        return JSONResponse({"success": True, "blocked_hosts": [], "blocked_categories": [], "blocked_users": []})


# ── Bandwidth ────────────────────────────────────────────────────────

@router.get("/api/url-analytics/bandwidth",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_bandwidth(hours: int = Query(24, ge=1, le=720), limit: int = Query(15, ge=5, le=50)):
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()

        # By user
        usr_q = f"""
        SELECT src_ip, any(src_user) as username,
               sum(sent_bytes) as sent, sum(recv_bytes) as recv,
               sum(sent_bytes + recv_bytes) as total_bytes,
               count() as requests
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR {sc}
        GROUP BY src_ip ORDER BY total_bytes DESC LIMIT {limit}
        """
        by_user = [{"src_ip": r["src_ip"], "username": r["username"] or "",
                    "sent": _safe(r["sent"]), "recv": _safe(r["recv"]),
                    "total_bytes": _safe(r["total_bytes"]),
                    "requests": _safe(r["requests"])}
                   for r in client.query(usr_q).named_results()]

        # By hostname
        host_q = f"""
        SELECT hostname,
               sum(sent_bytes + recv_bytes) as total_bytes,
               sum(recv_bytes) as recv, sum(sent_bytes) as sent,
               count() as requests, uniqExact(src_ip) as users
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND hostname != '' {sc}
        GROUP BY hostname ORDER BY total_bytes DESC LIMIT {limit}
        """
        by_host = [{"hostname": r["hostname"],
                    "total_bytes": _safe(r["total_bytes"]),
                    "recv": _safe(r["recv"]), "sent": _safe(r["sent"]),
                    "requests": _safe(r["requests"]),
                    "users": _safe(r["users"])}
                   for r in client.query(host_q).named_results()]

        return JSONResponse({"success": True, "by_user": by_user, "by_hostname": by_host})
    except Exception as e:
        logger.error(f"Bandwidth error: {e}")
        return JSONResponse({"success": True, "by_user": [], "by_hostname": []})
