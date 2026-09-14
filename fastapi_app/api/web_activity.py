"""
Web Activity — Fastvue-style reporting over the unified `url_logs` table.

One filter model drives every endpoint (time window, Site Clean, user, site,
category, action, productivity rating, free-text search) so any number on the
page can be clicked to narrow every other number. Report sections:

  summary / timeline / productivity          — overview
  users, user                                 — people and per-user profile
  sites, site                                 — sites (grouped by registrable
                                                domain) and per-site profile
  categories                                  — with productivity ratings
  searches                                    — search terms lifted from URLs
  blocked                                     — denied attempts bundle
  bandwidth                                   — session-deduplicated bytes
  logs                                        — raw rows (JSON or CSV)

Bandwidth: FortiGate writes several session-update rows per session with
*cumulative* byte counters; bytes are always reduced with max() per
(src_ip, session_id) before summing. Browsing time is the number of distinct
active minutes — the same approximation Fastvue uses.
"""

import csv
import io
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from ..core.permissions import require_min_role
from ..db.clickhouse import ClickHouseClient
from ..services.siteclean import build_siteclean_where
from .url_dashboard import PRODUCTIVITY_MAP, BLOCKED_ACTIONS, VALID_CAT, _safe

logger = logging.getLogger(__name__)

router = APIRouter(tags=["web-activity"])

_QUERY_SETTINGS = {
    'max_execution_time': 30,
    'use_query_cache': 1,
    'query_cache_ttl': 60,
    'query_cache_nondeterministic_function_handling': 'save',
}

PRODUCTIVITY_CLASSES = ("productive", "neutral", "unproductive", "risky")

# "Site" = registrable domain (www.google.com and mail.google.com are one
# site), falling back to the hostname for bare IPs.
SITE_EXPR = ("if(match(hostname, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+$') OR cutToFirstSignificantSubdomain(hostname) = '', "
             "hostname, cutToFirstSignificantSubdomain(hostname))")
WHO_EXPR = "if(src_user != '', src_user, src_ip)"
SEARCH_HOSTS = ("hostname LIKE '%google.%' OR hostname LIKE '%bing.com%' OR hostname LIKE '%duckduckgo.com%' "
                "OR hostname LIKE '%yahoo.com%' OR hostname LIKE '%youtube.com%' OR hostname LIKE '%yandex.%'")
SEARCH_TERM_EXPR = ("decodeURLComponent(if(extractURLParameter(url, 'q') != '', extractURLParameter(url, 'q'), "
                    "if(extractURLParameter(url, 'search_query') != '', extractURLParameter(url, 'search_query'), "
                    "extractURLParameter(url, 'p'))))")


def _productivity_expr() -> str:
    """multiIf(...) mapping url_category onto a productivity class."""
    buckets: dict[str, list[str]] = {c: [] for c in PRODUCTIVITY_CLASSES}
    for cat, cls in PRODUCTIVITY_MAP.items():
        buckets.setdefault(cls, []).append(cat.replace("'", "\\'"))
    parts = []
    for cls in ("productive", "unproductive", "risky"):
        vals = ", ".join(f"'{v}'" for v in buckets[cls])
        parts.append(f"lower(url_category) IN ({vals}), '{cls}'")
    return "multiIf(" + ", ".join(parts) + ", 'neutral')"


PROD_EXPR = _productivity_expr()

_CIDR_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
_IP_PREFIX_RE = re.compile(r'^(\d{1,3}\.){1,3}\d{0,3}$')


class Filters:
    """Parsed request filters + the WHERE clause they compile to."""

    def __init__(self, hours: int, start: Optional[str], end: Optional[str], clean: bool,
                 user: Optional[str], site: Optional[str], host: Optional[str],
                 category: Optional[str], action: Optional[str], productivity: Optional[str],
                 q: Optional[str], vendor: Optional[str], named: bool = False):
        self.params: dict = {}
        self.clauses: list[str] = []
        now = datetime.now(timezone.utc)
        self.start = self.end = None
        if start:
            try:
                self.start = datetime.fromisoformat(start.replace('Z', '+00:00'))
            except ValueError:
                pass
        if end:
            try:
                self.end = datetime.fromisoformat(end.replace('Z', '+00:00'))
            except ValueError:
                pass
        if self.start:
            self.clauses.append(f"timestamp >= '{self.start.strftime('%Y-%m-%d %H:%M:%S')}'")
            if self.end:
                self.clauses.append(f"timestamp <= '{self.end.strftime('%Y-%m-%d %H:%M:%S')}'")
            self.window_seconds = int(((self.end or now) - self.start).total_seconds())
        else:
            self.clauses.append(f"timestamp > now() - INTERVAL {int(hours)} HOUR")
            self.window_seconds = int(hours) * 3600
        self.window_seconds = max(60, self.window_seconds)
        self.hours = max(1, self.window_seconds // 3600)

        self.clean = clean
        if vendor in ('fortinet', 'paloalto'):
            self.clauses.append("vendor = {vendor:String}")
            self.params['vendor'] = vendor
        if user:
            self.clauses.append("(src_user = {user:String} OR src_ip = {user:String})")
            self.params['user'] = user
        if site:
            self.clauses.append(f"{SITE_EXPR} = {{site:String}}")
            self.params['site'] = site
        if host:
            self.clauses.append("hostname = {host:String}")
            self.params['host'] = host
        if category:
            self.clauses.append("url_category = {category:String}")
            self.params['category'] = category
        if action == 'blocked':
            self.clauses.append(f"action IN {BLOCKED_ACTIONS}")
        elif action == 'allowed':
            self.clauses.append(f"action NOT IN {BLOCKED_ACTIONS}")
        elif action:
            self.clauses.append("action = {action:String}")
            self.params['action'] = action
        if productivity in PRODUCTIVITY_CLASSES:
            self.clauses.append(f"{PROD_EXPR} = '{productivity}'")
        if named:
            self.clauses.append("src_user != ''")
        if q and q.strip():
            self.clauses.append(self._search_clause(q.strip()))
        self.user, self.site, self.host, self.category = user, site, host, category
        self.action, self.productivity, self.q = action, productivity, q

    def _search_clause(self, term: str) -> str:
        if _CIDR_RE.match(term):
            self.params['cidr'] = term
            return "(isIPAddressInRange(src_ip, {cidr:String}) OR isIPAddressInRange(dest_ip, {cidr:String}))"
        if _IP_PREFIX_RE.match(term) and '.' in term:
            self.params['ippfx'] = term.rstrip('.') + '%'
            return "(src_ip LIKE {ippfx:String} OR dest_ip LIKE {ippfx:String})"
        self.params['q'] = f"%{term}%"
        url_match = "url ILIKE {q:String}"
        if any(ord(c) > 127 for c in term):
            url_match = "decodeURLComponent(url) ILIKE {q:String}"
        return (f"(src_user ILIKE {{q:String}} OR src_ip ILIKE {{q:String}} OR hostname ILIKE {{q:String}} "
                f"OR {url_match} OR url_category ILIKE {{q:String}})")

    async def where(self) -> str:
        sql = " AND ".join(self.clauses)
        if self.clean:
            sc = await build_siteclean_where()
            if sc:
                sql += " " + sc
        return sql

    @property
    def bucket_seconds(self) -> int:
        """Timeline resolution: ~100 points per window, on round boundaries."""
        for step in (60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400):
            if self.window_seconds / step <= 120:
                return step
        return 86400


def _filters(hours: int = Query(24, ge=1, le=744), start: Optional[str] = None, end: Optional[str] = None,
             clean: bool = Query(True), user: Optional[str] = None, site: Optional[str] = None,
             host: Optional[str] = None, category: Optional[str] = None, action: Optional[str] = None,
             productivity: Optional[str] = None, q: Optional[str] = None,
             vendor: Optional[str] = None, named: bool = Query(False)) -> Filters:
    return Filters(hours, start, end, clean, user, site, host, category, action, productivity, q, vendor, named)


def _run(sql: str, params: dict):
    client = ClickHouseClient.get_client()
    return list(client.query(sql, parameters=params, settings=_QUERY_SETTINGS).named_results())


def _row(rows, default=None):
    return rows[0] if rows else (default or {})


def _clean_rows(rows):
    return [{k: _safe(v) if isinstance(v, (int, float)) or v is None else v for k, v in r.items()} for r in rows]


# Session-deduplicated bandwidth over the filtered rows: max() per session,
# with per-session dimensions so callers can regroup by user or site.
def _session_cte(where: str) -> str:
    return f"""
    sessions AS (
        SELECT src_ip, session_id,
               any({WHO_EXPR})   AS who,
               any({SITE_EXPR})  AS site,
               max(sent_bytes)   AS sent,
               max(recv_bytes)   AS recv
        FROM url_logs
        WHERE {where}
        GROUP BY src_ip, session_id
    )"""


# ============================================================
# Overview
# ============================================================

@router.get("/api/web-activity/summary", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_summary(f: Filters = Depends(_filters)):
    try:
        where = await f.where()
        s = _row(_run(f"""
            SELECT count()                                   AS requests,
                   uniq({WHO_EXPR})                          AS users,
                   uniq({SITE_EXPR})                         AS sites,
                   uniq(hostname)                            AS hosts,
                   countIf(action IN {BLOCKED_ACTIONS})      AS blocked,
                   uniq(toStartOfMinute(timestamp))          AS active_minutes,
                   countIf({PROD_EXPR} = 'productive')       AS productive,
                   countIf({PROD_EXPR} = 'unproductive')     AS unproductive,
                   countIf({PROD_EXPR} = 'risky')            AS risky,
                   countIf({SEARCH_HOSTS}) > 0               AS _has_search,
                   uniq(url_category)                        AS categories
            FROM url_logs WHERE {where}""", f.params))
        bw = _row(_run(f"WITH {_session_cte(where)} SELECT sum(sent) AS sent, sum(recv) AS recv FROM sessions", f.params))
        noise = 0
        if f.clean:
            # How much the Site Clean rules are hiding for this window/filters.
            f_raw = " AND ".join(f.clauses)
            total_raw = _row(_run(f"SELECT count() AS c FROM url_logs WHERE {f_raw}", f.params)).get('c', 0)
            noise = max(0, _safe(total_raw) - _safe(s.get('requests')))
        return JSONResponse({"success": True, "summary": {
            "requests": _safe(s.get('requests')), "users": _safe(s.get('users')),
            "sites": _safe(s.get('sites')), "hosts": _safe(s.get('hosts')),
            "blocked": _safe(s.get('blocked')), "active_minutes": _safe(s.get('active_minutes')),
            "categories": _safe(s.get('categories')),
            "productive": _safe(s.get('productive')), "unproductive": _safe(s.get('unproductive')),
            "risky": _safe(s.get('risky')),
            "sent": _safe(bw.get('sent')), "recv": _safe(bw.get('recv')),
            "bandwidth": _safe(bw.get('sent')) + _safe(bw.get('recv')),
            "noise_hidden": noise,
            "window_seconds": f.window_seconds,
        }})
    except Exception as e:
        logger.error(f"web-activity summary: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/timeline", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_timeline(f: Filters = Depends(_filters)):
    try:
        where = await f.where()
        step = f.bucket_seconds
        rows = _run(f"""
            SELECT toStartOfInterval(timestamp, INTERVAL {step} SECOND) AS t,
                   count()                              AS requests,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked,
                   uniq({WHO_EXPR})                     AS users,
                   countIf({PROD_EXPR} = 'unproductive') AS unproductive,
                   countIf({PROD_EXPR} = 'risky')        AS risky
            FROM url_logs WHERE {where}
            GROUP BY t ORDER BY t""", f.params)
        return JSONResponse({"success": True, "step": step, "points": [
            {"t": r['t'].isoformat(), "requests": _safe(r['requests']), "blocked": _safe(r['blocked']),
             "users": _safe(r['users']), "unproductive": _safe(r['unproductive']), "risky": _safe(r['risky'])}
            for r in rows]})
    except Exception as e:
        logger.error(f"web-activity timeline: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/productivity", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_productivity(f: Filters = Depends(_filters)):
    """Share of requests, users and browsing minutes per productivity class."""
    try:
        where = await f.where()
        rows = _run(f"""
            SELECT {PROD_EXPR} AS cls, count() AS requests, uniq({WHO_EXPR}) AS users,
                   uniq({WHO_EXPR}, toStartOfMinute(timestamp)) AS minutes,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked
            FROM url_logs WHERE {where} GROUP BY cls""", f.params)
        by = {r['cls']: r for r in rows}
        return JSONResponse({"success": True, "classes": [
            {"cls": c, "requests": _safe(by.get(c, {}).get('requests')), "users": _safe(by.get(c, {}).get('users')),
             "minutes": _safe(by.get(c, {}).get('minutes')), "blocked": _safe(by.get(c, {}).get('blocked'))}
            for c in PRODUCTIVITY_CLASSES]})
    except Exception as e:
        logger.error(f"web-activity productivity: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Users
# ============================================================

_USER_SORTS = {"requests": "requests", "minutes": "minutes", "bandwidth": "bandwidth",
               "blocked": "blocked", "sites": "sites", "unproductive": "unproductive"}


@router.get("/api/web-activity/users", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_users(f: Filters = Depends(_filters), limit: int = Query(25, ge=1, le=500),
                    sort: str = Query("requests")):
    try:
        where = await f.where()
        order = _USER_SORTS.get(sort, "requests")
        rows = _run(f"""
            WITH {_session_cte(where)}
            SELECT who,
                   groupUniqArray(3)(src_ip)                    AS ips,
                   sum(req)                                     AS requests,
                   uniqMerge(sites_st)                          AS sites,
                   uniqMerge(min_st)                            AS minutes,
                   sum(blk)                                     AS blocked,
                   sum(prod)                                    AS productive,
                   sum(unprod)                                  AS unproductive,
                   sum(risky)                                   AS risky,
                   topKMerge(3)(top_st)                         AS top_sites,
                   any(bw)                                      AS bandwidth
            FROM (
                SELECT {WHO_EXPR} AS who, src_ip, count() AS req,
                       uniqState({SITE_EXPR}) AS sites_st,
                       uniqState(toStartOfMinute(timestamp)) AS min_st,
                       countIf(action IN {BLOCKED_ACTIONS}) AS blk,
                       countIf({PROD_EXPR} = 'productive') AS prod,
                       countIf({PROD_EXPR} = 'unproductive') AS unprod,
                       countIf({PROD_EXPR} = 'risky') AS risky,
                       topKState(3)({SITE_EXPR}) AS top_st,
                       0 AS bw
                FROM url_logs WHERE {where}
                GROUP BY who, src_ip
                UNION ALL
                SELECT who, src_ip, 0, uniqState(''), uniqState(toStartOfMinute(toDateTime64(0, 3))),
                       0, 0, 0, 0, topKState(3)(''), sum(sent + recv)
                FROM sessions GROUP BY who, src_ip
            )
            GROUP BY who
            ORDER BY {order} DESC
            LIMIT {int(limit)}""", f.params)
        # The UNION trick leaves an empty '' site/minute in the merged states;
        # subtract it so counts are exact for what the user actually did.
        out = []
        for r in rows:
            out.append({
                "user": r['who'], "ips": list(r['ips'] or []),
                "requests": _safe(r['requests']), "sites": max(0, _safe(r['sites']) - 1),
                "minutes": max(0, _safe(r['minutes']) - 1), "blocked": _safe(r['blocked']),
                "productive": _safe(r['productive']), "unproductive": _safe(r['unproductive']),
                "risky": _safe(r['risky']), "bandwidth": _safe(r['bandwidth']),
                "top_sites": [s for s in (r['top_sites'] or []) if s],
            })
        # any(bw) picks an arbitrary branch row; recompute bandwidth precisely.
        bw_rows = _run(f"WITH {_session_cte(where)} SELECT who, sum(sent + recv) AS bw FROM sessions GROUP BY who",
                       f.params)
        bw_by = {r['who']: _safe(r['bw']) for r in bw_rows}
        for u in out:
            u['bandwidth'] = bw_by.get(u['user'], 0)
        if order == 'bandwidth':
            out.sort(key=lambda u: -u['bandwidth'])
        return JSONResponse({"success": True, "users": out})
    except Exception as e:
        logger.error(f"web-activity users: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/user", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_user(user: str = Query(...), f: Filters = Depends(_filters)):
    """Everything about one person (or IP) in the window."""
    try:
        f.clauses.append("(src_user = {who:String} OR src_ip = {who:String})")
        f.params['who'] = user
        where = await f.where()
        s = _row(_run(f"""
            SELECT count() AS requests, uniq({SITE_EXPR}) AS sites, uniq(toStartOfMinute(timestamp)) AS minutes,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked, min(timestamp) AS first_seen,
                   max(timestamp) AS last_seen, groupUniqArray(5)(src_ip) AS ips,
                   groupUniqArray(3)(src_user) AS names, groupUniqArray(3)(profile) AS profiles,
                   groupUniqArray(3)(device_name) AS devices,
                   countIf({PROD_EXPR} = 'productive') AS productive,
                   countIf({PROD_EXPR} = 'neutral') AS neutral,
                   countIf({PROD_EXPR} = 'unproductive') AS unproductive,
                   countIf({PROD_EXPR} = 'risky') AS risky
            FROM url_logs WHERE {where}""", f.params))
        bw = _row(_run(f"WITH {_session_cte(where)} SELECT sum(sent) AS sent, sum(recv) AS recv FROM sessions", f.params))
        step = f.bucket_seconds
        timeline = _run(f"""
            SELECT toStartOfInterval(timestamp, INTERVAL {step} SECOND) AS t, count() AS requests,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked, uniq(toStartOfMinute(timestamp)) AS minutes
            FROM url_logs WHERE {where} GROUP BY t ORDER BY t""", f.params)
        hours = _run(f"""
            SELECT toHour(timestamp) AS h, count() AS requests, uniq(toStartOfMinute(timestamp)) AS minutes
            FROM url_logs WHERE {where} GROUP BY h ORDER BY h""", f.params)
        categories = _run(f"""
            SELECT url_category AS category, {PROD_EXPR} AS cls, count() AS requests,
                   uniq(toStartOfMinute(timestamp)) AS minutes, countIf(action IN {BLOCKED_ACTIONS}) AS blocked
            FROM url_logs WHERE {where} AND {VALID_CAT} GROUP BY category, cls ORDER BY requests DESC LIMIT 20""", f.params)
        sites = _run(f"""
            WITH {_session_cte(where)}
            SELECT site, any(category) AS category, any(cls) AS cls, sum(requests) AS requests,
                   sum(minutes) AS minutes, sum(blocked) AS blocked, sum(bw) AS bandwidth
            FROM (
                SELECT {SITE_EXPR} AS site, any(url_category) AS category, any({PROD_EXPR}) AS cls,
                       count() AS requests, uniq(toStartOfMinute(timestamp)) AS minutes,
                       countIf(action IN {BLOCKED_ACTIONS}) AS blocked, 0 AS bw
                FROM url_logs WHERE {where} GROUP BY site
                UNION ALL
                SELECT site, '', '', 0, 0, 0, sum(sent + recv) FROM sessions GROUP BY site
            ) GROUP BY site ORDER BY requests DESC LIMIT 25""", f.params)
        searches = _run(f"""
            SELECT {SEARCH_TERM_EXPR} AS term, any(hostname) AS engine, count() AS hits, max(timestamp) AS last_seen
            FROM url_logs WHERE {where} AND ({SEARCH_HOSTS}) GROUP BY term HAVING term != ''
            ORDER BY last_seen DESC LIMIT 30""", f.params)
        blocked = _run(f"""
            SELECT {SITE_EXPR} AS site, url_category AS category, count() AS hits, max(timestamp) AS last_seen
            FROM url_logs WHERE {where} AND action IN {BLOCKED_ACTIONS}
            GROUP BY site, category ORDER BY hits DESC LIMIT 20""", f.params)
        recent = _run(f"""
            SELECT timestamp, hostname, url, url_category AS category, action, http_method, sent_bytes, recv_bytes
            FROM url_logs WHERE {where} ORDER BY timestamp DESC LIMIT 50""", f.params)

        def iso(v):
            return v.isoformat() if hasattr(v, 'isoformat') else v

        return JSONResponse({"success": True, "user": user, "summary": {
            "requests": _safe(s.get('requests')), "sites": _safe(s.get('sites')),
            "minutes": _safe(s.get('minutes')), "blocked": _safe(s.get('blocked')),
            "first_seen": iso(s.get('first_seen')), "last_seen": iso(s.get('last_seen')),
            "ips": list(s.get('ips') or []), "names": [n for n in (s.get('names') or []) if n],
            "profiles": [p for p in (s.get('profiles') or []) if p],
            "devices": [d for d in (s.get('devices') or []) if d],
            "productive": _safe(s.get('productive')), "neutral": _safe(s.get('neutral')),
            "unproductive": _safe(s.get('unproductive')), "risky": _safe(s.get('risky')),
            "bandwidth": _safe(bw.get('sent')) + _safe(bw.get('recv')),
            "sent": _safe(bw.get('sent')), "recv": _safe(bw.get('recv')),
        },
            "step": step,
            "timeline": [{"t": iso(r['t']), "requests": _safe(r['requests']), "blocked": _safe(r['blocked']),
                          "minutes": _safe(r['minutes'])} for r in timeline],
            "hours": [{"h": int(r['h']), "requests": _safe(r['requests']), "minutes": _safe(r['minutes'])} for r in hours],
            "categories": _clean_rows(categories),
            "sites": _clean_rows(sites),
            "searches": [{"term": r['term'], "engine": r['engine'], "hits": _safe(r['hits']), "last_seen": iso(r['last_seen'])}
                         for r in searches],
            "blocked": [{"site": r['site'], "category": r['category'], "hits": _safe(r['hits']), "last_seen": iso(r['last_seen'])}
                        for r in blocked],
            "recent": [{"timestamp": iso(r['timestamp']), "hostname": r['hostname'], "url": r['url'],
                        "category": r['category'], "action": r['action'], "method": r['http_method'],
                        "bytes": _safe(r['sent_bytes']) + _safe(r['recv_bytes'])} for r in recent],
        })
    except Exception as e:
        logger.error(f"web-activity user: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Sites & categories
# ============================================================

_SITE_SORTS = {"requests": "requests", "users": "users", "minutes": "minutes",
               "bandwidth": "bandwidth", "blocked": "blocked"}


@router.get("/api/web-activity/sites", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_sites(f: Filters = Depends(_filters), limit: int = Query(25, ge=1, le=500),
                    sort: str = Query("requests")):
    try:
        where = await f.where()
        order = _SITE_SORTS.get(sort, "requests")
        rows = _run(f"""
            WITH {_session_cte(where)}
            SELECT site, anyIf(category, category != '') AS category, anyIf(cls, cls != '') AS cls,
                   sum(requests) AS requests, uniqMerge(users_st) AS users, sum(hosts) AS hosts,
                   sum(minutes) AS minutes, sum(blocked) AS blocked, sum(bw) AS bandwidth
            FROM (
                SELECT {SITE_EXPR} AS site, topK(1)(url_category)[1] AS category, topK(1)({PROD_EXPR})[1] AS cls,
                       count() AS requests, uniqState({WHO_EXPR}) AS users_st, uniq(hostname) AS hosts,
                       uniq({WHO_EXPR}, toStartOfMinute(timestamp)) AS minutes,
                       countIf(action IN {BLOCKED_ACTIONS}) AS blocked, 0 AS bw
                FROM url_logs WHERE {where} GROUP BY site
                UNION ALL
                SELECT site, '', '', 0, uniqState(''), 0, 0, 0, sum(sent + recv) FROM sessions GROUP BY site
            )
            GROUP BY site
            ORDER BY {order} DESC
            LIMIT {int(limit)}""", f.params)
        return JSONResponse({"success": True, "sites": [
            {"site": r['site'], "category": r['category'] or '', "cls": r['cls'] or 'neutral',
             "requests": _safe(r['requests']), "users": max(0, _safe(r['users']) - 1), "hosts": _safe(r['hosts']),
             "minutes": _safe(r['minutes']), "blocked": _safe(r['blocked']), "bandwidth": _safe(r['bandwidth'])}
            for r in rows]})
    except Exception as e:
        logger.error(f"web-activity sites: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/site", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_site(site: str = Query(...), f: Filters = Depends(_filters)):
    try:
        f.clauses.append(f"{SITE_EXPR} = {{site_key:String}}")
        f.params['site_key'] = site
        where = await f.where()
        s = _row(_run(f"""
            SELECT count() AS requests, uniq({WHO_EXPR}) AS users, uniq(hostname) AS hosts,
                   uniq({WHO_EXPR}, toStartOfMinute(timestamp)) AS minutes,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked, min(timestamp) AS first_seen, max(timestamp) AS last_seen,
                   topK(3)(url_category) AS categories, any({PROD_EXPR}) AS cls
            FROM url_logs WHERE {where}""", f.params))
        bw = _row(_run(f"WITH {_session_cte(where)} SELECT sum(sent) AS sent, sum(recv) AS recv FROM sessions", f.params))
        step = f.bucket_seconds
        timeline = _run(f"""
            SELECT toStartOfInterval(timestamp, INTERVAL {step} SECOND) AS t, count() AS requests,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked, uniq({WHO_EXPR}) AS users
            FROM url_logs WHERE {where} GROUP BY t ORDER BY t""", f.params)
        users = _run(f"""
            WITH {_session_cte(where)}
            SELECT who, sum(requests) AS requests, sum(minutes) AS minutes, sum(blocked) AS blocked,
                   max(last_seen) AS last_seen, sum(bw) AS bandwidth
            FROM (
                SELECT {WHO_EXPR} AS who, count() AS requests, uniq(toStartOfMinute(timestamp)) AS minutes,
                       countIf(action IN {BLOCKED_ACTIONS}) AS blocked, max(timestamp) AS last_seen, 0 AS bw
                FROM url_logs WHERE {where} GROUP BY who
                UNION ALL
                SELECT who, 0, 0, 0, toDateTime64(0, 3), sum(sent + recv) FROM sessions GROUP BY who
            ) GROUP BY who ORDER BY requests DESC LIMIT 25""", f.params)
        hosts = _run(f"""
            SELECT hostname, count() AS requests, uniq({WHO_EXPR}) AS users, countIf(action IN {BLOCKED_ACTIONS}) AS blocked
            FROM url_logs WHERE {where} GROUP BY hostname ORDER BY requests DESC LIMIT 20""", f.params)
        urls = _run(f"""
            SELECT url, count() AS hits, uniq({WHO_EXPR}) AS users, any(action) AS action
            FROM url_logs WHERE {where} AND url != '' GROUP BY url ORDER BY hits DESC LIMIT 20""", f.params)
        actions = _run(f"SELECT action, count() AS c FROM url_logs WHERE {where} GROUP BY action ORDER BY c DESC", f.params)

        def iso(v):
            return v.isoformat() if hasattr(v, 'isoformat') else v

        return JSONResponse({"success": True, "site": site, "summary": {
            "requests": _safe(s.get('requests')), "users": _safe(s.get('users')), "hosts": _safe(s.get('hosts')),
            "minutes": _safe(s.get('minutes')), "blocked": _safe(s.get('blocked')),
            "first_seen": iso(s.get('first_seen')), "last_seen": iso(s.get('last_seen')),
            "categories": list(s.get('categories') or []), "cls": s.get('cls') or 'neutral',
            "bandwidth": _safe(bw.get('sent')) + _safe(bw.get('recv')),
        },
            "step": step,
            "timeline": [{"t": iso(r['t']), "requests": _safe(r['requests']), "blocked": _safe(r['blocked']),
                          "users": _safe(r['users'])} for r in timeline],
            "users": [{"user": r['who'], "requests": _safe(r['requests']), "minutes": _safe(r['minutes']),
                       "blocked": _safe(r['blocked']), "last_seen": iso(r['last_seen']),
                       "bandwidth": _safe(r['bandwidth'])} for r in users],
            "hosts": _clean_rows(hosts),
            "urls": _clean_rows(urls),
            "actions": [{"action": r['action'], "count": _safe(r['c'])} for r in actions],
        })
    except Exception as e:
        logger.error(f"web-activity site: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/categories", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_categories(f: Filters = Depends(_filters), limit: int = Query(60, ge=1, le=200)):
    try:
        where = await f.where()
        rows = _run(f"""
            SELECT url_category AS category, any({PROD_EXPR}) AS cls, count() AS requests,
                   uniq({WHO_EXPR}) AS users, uniq({SITE_EXPR}) AS sites,
                   uniq({WHO_EXPR}, toStartOfMinute(timestamp)) AS minutes,
                   countIf(action IN {BLOCKED_ACTIONS}) AS blocked
            FROM url_logs WHERE {where} AND {VALID_CAT}
            GROUP BY category ORDER BY requests DESC LIMIT {int(limit)}""", f.params)
        return JSONResponse({"success": True, "categories": _clean_rows(rows)})
    except Exception as e:
        logger.error(f"web-activity categories: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Searches, blocked, bandwidth
# ============================================================

@router.get("/api/web-activity/searches", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_searches(f: Filters = Depends(_filters), limit: int = Query(100, ge=1, le=500)):
    try:
        where = await f.where()
        rows = _run(f"""
            SELECT {SEARCH_TERM_EXPR} AS term, count() AS hits, uniq({WHO_EXPR}) AS users,
                   groupUniqArray(3)({WHO_EXPR}) AS sample_users, topK(1)({SITE_EXPR})[1] AS engine,
                   max(timestamp) AS last_seen
            FROM url_logs WHERE {where} AND ({SEARCH_HOSTS})
            GROUP BY term HAVING term != '' ORDER BY last_seen DESC LIMIT {int(limit)}""", f.params)
        return JSONResponse({"success": True, "searches": [
            {"term": r['term'], "hits": _safe(r['hits']), "users": _safe(r['users']),
             "sample_users": list(r['sample_users'] or []), "engine": r['engine'] or '',
             "last_seen": r['last_seen'].isoformat()} for r in rows]})
    except Exception as e:
        logger.error(f"web-activity searches: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/blocked", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_blocked(f: Filters = Depends(_filters)):
    try:
        f.clauses.append(f"action IN {BLOCKED_ACTIONS}")
        where = await f.where()
        s = _row(_run(f"SELECT count() AS blocked, uniq({WHO_EXPR}) AS users, uniq({SITE_EXPR}) AS sites, "
                      f"uniq(url_category) AS categories FROM url_logs WHERE {where}", f.params))
        users = _run(f"SELECT {WHO_EXPR} AS user, count() AS hits, uniq({SITE_EXPR}) AS sites, topK(3)({SITE_EXPR}) AS top_sites "
                     f"FROM url_logs WHERE {where} GROUP BY user ORDER BY hits DESC LIMIT 20", f.params)
        sites = _run(f"SELECT {SITE_EXPR} AS site, topK(1)(url_category)[1] AS category, count() AS hits, uniq({WHO_EXPR}) AS users "
                     f"FROM url_logs WHERE {where} GROUP BY site ORDER BY hits DESC LIMIT 20", f.params)
        cats = _run(f"SELECT url_category AS category, any({PROD_EXPR}) AS cls, count() AS hits, uniq({WHO_EXPR}) AS users "
                    f"FROM url_logs WHERE {where} AND {VALID_CAT} GROUP BY category ORDER BY hits DESC LIMIT 20", f.params)
        reasons = _run(f"SELECT msg AS reason, count() AS hits FROM url_logs WHERE {where} AND msg != '' "
                       f"GROUP BY reason ORDER BY hits DESC LIMIT 8", f.params)
        recent = _run(f"SELECT timestamp, {WHO_EXPR} AS user, hostname, url, url_category AS category, profile "
                      f"FROM url_logs WHERE {where} ORDER BY timestamp DESC LIMIT 50", f.params)
        return JSONResponse({"success": True, "summary": {k: _safe(s.get(k)) for k in ('blocked', 'users', 'sites', 'categories')},
                             "users": [{"user": r['user'], "hits": _safe(r['hits']), "sites": _safe(r['sites']),
                                        "top_sites": list(r['top_sites'] or [])} for r in users],
                             "sites": _clean_rows(sites), "categories": _clean_rows(cats), "reasons": _clean_rows(reasons),
                             "recent": [{"timestamp": r['timestamp'].isoformat(), "user": r['user'], "hostname": r['hostname'],
                                         "url": r['url'], "category": r['category'], "profile": r['profile']} for r in recent]})
    except Exception as e:
        logger.error(f"web-activity blocked: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/bandwidth", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_bandwidth(f: Filters = Depends(_filters)):
    try:
        where = await f.where()
        cte = _session_cte(where)
        users = _run(f"WITH {cte} SELECT who AS user, sum(sent) AS sent, sum(recv) AS recv, count() AS sessions "
                     f"FROM sessions GROUP BY who ORDER BY sent + recv DESC LIMIT 20", f.params)
        sites = _run(f"WITH {cte} SELECT site, sum(sent) AS sent, sum(recv) AS recv, uniq(who) AS users "
                     f"FROM sessions GROUP BY site ORDER BY sent + recv DESC LIMIT 20", f.params)
        step = f.bucket_seconds
        timeline = _run(f"""
            SELECT toStartOfInterval(ts, INTERVAL {step} SECOND) AS t, sum(sent) AS sent, sum(recv) AS recv
            FROM (SELECT src_ip, session_id, max(timestamp) AS ts, max(sent_bytes) AS sent, max(recv_bytes) AS recv
                  FROM url_logs WHERE {where} GROUP BY src_ip, session_id)
            GROUP BY t ORDER BY t""", f.params)
        cats = _run(f"""
            SELECT category, sum(sent + recv) AS bytes FROM (
                SELECT src_ip, session_id, any(url_category) AS category, max(sent_bytes) AS sent, max(recv_bytes) AS recv
                FROM url_logs WHERE {where} GROUP BY src_ip, session_id)
            WHERE category != '' GROUP BY category ORDER BY bytes DESC LIMIT 12""", f.params)
        return JSONResponse({"success": True, "step": step,
                             "users": _clean_rows(users), "sites": _clean_rows(sites), "categories": _clean_rows(cats),
                             "timeline": [{"t": r['t'].isoformat(), "sent": _safe(r['sent']), "recv": _safe(r['recv'])} for r in timeline]})
    except Exception as e:
        logger.error(f"web-activity bandwidth: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Raw logs (table + CSV)
# ============================================================

_LOG_COLS = ("timestamp", "src_user", "src_ip", "hostname", "url", "url_category", "action", "http_method",
             "sent_bytes", "recv_bytes", "dest_ip", "dest_port", "profile", "policy", "user_agent", "referrer",
             "device_name", "vendor", "request_type", "msg")


@router.get("/api/web-activity/logs", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_logs(f: Filters = Depends(_filters), limit: int = Query(100, ge=1, le=500),
                   offset: int = Query(0, ge=0), format: str = Query("json")):
    try:
        where = await f.where()
        cols = ", ".join(_LOG_COLS)
        if format == "csv":
            rows = _run(f"SELECT {cols} FROM url_logs WHERE {where} ORDER BY timestamp DESC LIMIT 50000", f.params)

            def gen():
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(_LOG_COLS)
                yield buf.getvalue(); buf.seek(0); buf.truncate(0)
                for r in rows:
                    w.writerow([r[c].isoformat() if hasattr(r[c], 'isoformat') else r[c] for c in _LOG_COLS])
                    yield buf.getvalue(); buf.seek(0); buf.truncate(0)
            return StreamingResponse(gen(), media_type="text/csv",
                                     headers={"Content-Disposition": "attachment; filename=web_activity.csv"})
        total = _row(_run(f"SELECT count() AS c FROM url_logs WHERE {where}", f.params)).get('c', 0)
        rows = _run(f"SELECT {cols} FROM url_logs WHERE {where} ORDER BY timestamp DESC LIMIT {int(limit)} OFFSET {int(offset)}",
                    f.params)
        out = []
        for r in rows:
            d = {c: (r[c].isoformat() if hasattr(r[c], 'isoformat') else r[c]) for c in _LOG_COLS}
            d['bytes'] = _safe(r['sent_bytes']) + _safe(r['recv_bytes'])
            d['site'] = r['hostname']
            out.append(d)
        return JSONResponse({"success": True, "total": _safe(total), "limit": limit, "offset": offset, "rows": out})
    except Exception as e:
        logger.error(f"web-activity logs: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/web-activity/facets", dependencies=[Depends(require_min_role("ANALYST"))])
async def api_facets(f: Filters = Depends(_filters)):
    """Values for the filter pickers, restricted to what exists in the window."""
    try:
        where = await f.where()
        cats = _run(f"SELECT url_category AS v, count() AS c FROM url_logs WHERE {where} AND {VALID_CAT} "
                    f"GROUP BY v ORDER BY c DESC LIMIT 80", f.params)
        actions = _run(f"SELECT action AS v, count() AS c FROM url_logs WHERE {where} GROUP BY v ORDER BY c DESC", f.params)
        users = _run(f"SELECT {WHO_EXPR} AS v, count() AS c FROM url_logs WHERE {where} GROUP BY v ORDER BY c DESC LIMIT 300",
                     f.params)
        return JSONResponse({"success": True,
                             "categories": [{"value": r['v'], "count": _safe(r['c'])} for r in cats],
                             "actions": [{"value": r['v'], "count": _safe(r['c'])} for r in actions],
                             "users": [{"value": r['v'], "count": _safe(r['c'])} for r in users]})
    except Exception as e:
        logger.error(f"web-activity facets: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
