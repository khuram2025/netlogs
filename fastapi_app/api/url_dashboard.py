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

# Filter clause used everywhere we read url_category. Excludes garbage values
# from truncated UDP syslog (leading `"`, length < 3) so dashboards and
# dropdowns only show real categories.
VALID_CAT = (
    "url_category != '' "
    "AND NOT startsWith(url_category, '\"') "
    "AND length(url_category) >= 3"
)


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
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {VALID_CAT} {sc}
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
               any(if({VALID_CAT}, url_category, '')) as category
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
        SELECT hostname, any(if({VALID_CAT}, url_category, '')) as category,
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
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND {blk} AND {VALID_CAT} {sc}
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


# ── Timeline (hourly buckets) ────────────────────────────────────────

@router.get("/api/url-analytics/timeline",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_timeline(hours: int = Query(24, ge=1, le=720)):
    """Hourly time-series with action breakdown + bandwidth, for area chart."""
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        # Bucket size: 5min if ≤6h, 1h if ≤7d, 1d if >7d
        if hours <= 6:
            bucket_sql = "toStartOfFiveMinute(timestamp)"
            bucket_size = "5m"
        elif hours <= 168:
            bucket_sql = "toStartOfHour(timestamp)"
            bucket_size = "1h"
        else:
            bucket_sql = "toStartOfDay(timestamp)"
            bucket_size = "1d"
        q = f"""
        SELECT {bucket_sql} as bucket,
               count() as total,
               countIf(action IN {BLOCKED_ACTIONS}) as blocked,
               countIf(action IN ('alert','warn','warning')) as alerted,
               countIf(action IN ('allow','passthrough','log','pass','accept')) as allowed,
               sum(recv_bytes) as recv,
               sum(sent_bytes) as sent,
               uniqExact(if(src_user != '', src_user, src_ip)) as users
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR {sc}
        GROUP BY bucket
        ORDER BY bucket ASC
        """
        rows = list(client.query(q).named_results())
        return JSONResponse({
            "success": True, "bucket_size": bucket_size,
            "timeline": [{
                "bucket": r["bucket"].isoformat() if hasattr(r["bucket"], "isoformat") else str(r["bucket"]),
                "total": _safe(r["total"]),
                "blocked": _safe(r["blocked"]),
                "alerted": _safe(r["alerted"]),
                "allowed": _safe(r["allowed"]),
                "recv": _safe(r["recv"]),
                "sent": _safe(r["sent"]),
                "users": _safe(r["users"]),
            } for r in rows]
        })
    except Exception as e:
        logger.error(f"Timeline error: {e}")
        return JSONResponse({"success": True, "timeline": [], "bucket_size": "1h"})


# ── Actions breakdown ───────────────────────────────────────────────

@router.get("/api/url-analytics/actions",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_actions(hours: int = Query(24, ge=1, le=720)):
    """Action distribution + HTTP method distribution + content type distribution."""
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()

        act_q = f"""
        SELECT action, count() as cnt
        FROM url_logs WHERE timestamp > now() - INTERVAL {hours} HOUR AND action != '' {sc}
        GROUP BY action ORDER BY cnt DESC
        """
        actions = [{"action": r["action"], "count": _safe(r["cnt"])}
                   for r in client.query(act_q).named_results()]

        mth_q = f"""
        SELECT http_method as method, count() as cnt
        FROM url_logs WHERE timestamp > now() - INTERVAL {hours} HOUR AND http_method != '' {sc}
        GROUP BY http_method ORDER BY cnt DESC LIMIT 10
        """
        methods = [{"method": r["method"], "count": _safe(r["cnt"])}
                   for r in client.query(mth_q).named_results()]

        # Vendor breakdown
        vnd_q = f"""
        SELECT vendor, count() as cnt
        FROM url_logs WHERE timestamp > now() - INTERVAL {hours} HOUR AND vendor != '' {sc}
        GROUP BY vendor ORDER BY cnt DESC
        """
        vendors = [{"vendor": r["vendor"], "count": _safe(r["cnt"])}
                   for r in client.query(vnd_q).named_results()]

        return JSONResponse({"success": True, "actions": actions, "methods": methods, "vendors": vendors})
    except Exception as e:
        logger.error(f"Actions error: {e}")
        return JSONResponse({"success": True, "actions": [], "methods": [], "vendors": []})


# ── Countries ───────────────────────────────────────────────────────

@router.get("/api/url-analytics/countries",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_countries(hours: int = Query(24, ge=1, le=720), limit: int = Query(15, ge=5, le=50)):
    """Top destination countries by request count."""
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT dest_country as country, count() as requests,
               sum(sent_bytes + recv_bytes) as bandwidth,
               uniqExact(src_ip) as users,
               countIf(action IN {BLOCKED_ACTIONS}) as blocked
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND dest_country != '' {sc}
        GROUP BY dest_country ORDER BY requests DESC LIMIT {limit}
        """
        rows = [{"country": r["country"], "requests": _safe(r["requests"]),
                 "bandwidth": _safe(r["bandwidth"]),
                 "users": _safe(r["users"]),
                 "blocked": _safe(r["blocked"])}
                for r in client.query(q).named_results()]
        return JSONResponse({"success": True, "countries": rows})
    except Exception as e:
        logger.error(f"Countries error: {e}")
        return JSONResponse({"success": True, "countries": []})


# ── Applications ────────────────────────────────────────────────────

@router.get("/api/url-analytics/applications",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_applications(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=5, le=50)):
    """Top applications recognised by firewall (Fortinet appcat / Palo Alto app)."""
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT application as app, count() as requests,
               uniqExact(src_ip) as users,
               sum(sent_bytes + recv_bytes) as bandwidth,
               countIf(action IN {BLOCKED_ACTIONS}) as blocked
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR AND application != '' {sc}
        GROUP BY application ORDER BY requests DESC LIMIT {limit}
        """
        rows = [{"application": r["app"], "requests": _safe(r["requests"]),
                 "users": _safe(r["users"]),
                 "bandwidth": _safe(r["bandwidth"]),
                 "blocked": _safe(r["blocked"])}
                for r in client.query(q).named_results()]
        return JSONResponse({"success": True, "applications": rows})
    except Exception as e:
        logger.error(f"Applications error: {e}")
        return JSONResponse({"success": True, "applications": []})


# ── Devices ─────────────────────────────────────────────────────────

@router.get("/api/url-analytics/devices",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_devices(hours: int = Query(24, ge=1, le=720), limit: int = Query(15, ge=5, le=50)):
    """Activity by reporting firewall device."""
    try:
        client = ClickHouseClient.get_client()
        sc = await _sc_where()
        q = f"""
        SELECT
            coalesce(nullIf(device_name, ''), device_ip) as device,
            any(vendor) as vendor,
            any(device_ip) as device_ip,
            count() as requests,
            uniqExact(src_ip) as users,
            uniqExact(hostname) as sites,
            sum(sent_bytes + recv_bytes) as bandwidth,
            countIf(action IN {BLOCKED_ACTIONS}) as blocked
        FROM url_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR {sc}
        GROUP BY device ORDER BY requests DESC LIMIT {limit}
        """
        rows = [{"device": r["device"], "vendor": r["vendor"] or "",
                 "device_ip": r["device_ip"] or "",
                 "requests": _safe(r["requests"]),
                 "users": _safe(r["users"]),
                 "sites": _safe(r["sites"]),
                 "bandwidth": _safe(r["bandwidth"]),
                 "blocked": _safe(r["blocked"])}
                for r in client.query(q).named_results()]
        return JSONResponse({"success": True, "devices": rows})
    except Exception as e:
        logger.error(f"Devices error: {e}")
        return JSONResponse({"success": True, "devices": []})


# ── DNS Overview (mini analytics integrated into URL Analytics page) ─

@router.get("/api/url-analytics/dns",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_dns_overview(hours: int = Query(24, ge=1, le=720)):
    """DNS-side overview: top domains, qtypes, sinkholed, NXDOMAIN, etc."""
    try:
        client = ClickHouseClient.get_client()
        tw = f"timestamp > now() - INTERVAL {hours} HOUR"

        sum_q = f"""
        SELECT count() as total,
               uniqExact(src_ip) as users,
               uniqExact(qname) as unique_domains,
               countIf(action IN ('sinkhole','block','blocked','deny','drop','reset-client','reset-server')) as blocked,
               countIf(severity IN ('critical','high')) as critical_high,
               countIf(action = 'sinkhole') as sinkholed
        FROM dns_logs WHERE {tw}
        """
        sr = list(client.query(sum_q).named_results())
        s = sr[0] if sr else {}

        # Top queried domains
        dom_q = f"""
        SELECT qname, count() as cnt, any(category) as category,
               any(action) as action, any(severity) as severity
        FROM dns_logs WHERE {tw} AND qname != ''
        GROUP BY qname ORDER BY cnt DESC LIMIT 15
        """
        domains = [{"domain": r["qname"], "count": _safe(r["cnt"]),
                    "category": r["category"] or "",
                    "action": r["action"] or "",
                    "severity": r["severity"] or ""}
                   for r in client.query(dom_q).named_results()]

        # Query type distribution
        qtype_q = f"""
        SELECT qtype, count() as cnt
        FROM dns_logs WHERE {tw} AND qtype != ''
        GROUP BY qtype ORDER BY cnt DESC LIMIT 8
        """
        qtypes = [{"qtype": r["qtype"], "count": _safe(r["cnt"])}
                  for r in client.query(qtype_q).named_results()]

        # Top sources
        src_q = f"""
        SELECT src_ip, any(src_user) as username, count() as cnt,
               uniqExact(qname) as unique_domains,
               countIf(action IN ('sinkhole','block','blocked','deny','drop')) as blocked
        FROM dns_logs WHERE {tw}
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """
        sources = [{"src_ip": r["src_ip"], "username": r["username"] or "",
                    "count": _safe(r["cnt"]),
                    "unique_domains": _safe(r["unique_domains"]),
                    "blocked": _safe(r["blocked"])}
                   for r in client.query(src_q).named_results()]

        return JSONResponse({"success": True,
                             "summary": {
                                 "total": _safe(s.get("total")),
                                 "users": _safe(s.get("users")),
                                 "unique_domains": _safe(s.get("unique_domains")),
                                 "blocked": _safe(s.get("blocked")),
                                 "sinkholed": _safe(s.get("sinkholed")),
                                 "critical_high": _safe(s.get("critical_high")),
                             },
                             "domains": domains,
                             "qtypes": qtypes,
                             "sources": sources})
    except Exception as e:
        logger.error(f"DNS overview error: {e}")
        return JSONResponse({"success": True, "summary": {}, "domains": [], "qtypes": [], "sources": []})
