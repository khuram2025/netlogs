"""
Threat & URL Filtering Dashboard — pages + JSON API.

Reads from `pa_threat_logs` (Palo Alto) combined with Fortinet UTM data
queried directly from `syslogs` via UNION ALL.
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

router = APIRouter(tags=["threats"])
templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request, "app_version": __version__}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = getattr(request.state, "_alert_count", 0)
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


def _safe(val, default=0):
    """Convert ClickHouse result to safe Python value."""
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
# Smart search clause builder for url_logs
# ============================================================

import re

_CIDR_RE = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$')
_IP_PREFIX_RE = re.compile(r'^(\d{1,3}\.){1,3}\d{0,3}$')


def _build_url_search_clause(search: str, params: dict) -> str:
    """Build a WHERE clause for the url_logs search box.

    Supports:
    - CIDR subnet:  172.20.0.0/16  → isIPAddressInRange on src_ip / dest_ip
    - IP prefix:    172.20.  or 10.11.30  → LIKE prefix% on src_ip / dest_ip
    - General text: username, URL, hostname, category → ILIKE %term%
    """
    term = search.strip()

    # ── CIDR notation (e.g. 172.20.0.0/16) ──
    if _CIDR_RE.match(term):
        params["cidr"] = term
        return (
            "(isIPAddressInRange(src_ip, {cidr:String}) "
            "OR isIPAddressInRange(dest_ip, {cidr:String}))"
        )

    # ── Partial IP prefix (e.g. "172.20." or "10.11.30") ──
    if _IP_PREFIX_RE.match(term) and '.' in term:
        prefix = term.rstrip('.')
        params["ippfx"] = prefix + '%'
        return "(src_ip LIKE {ippfx:String} OR dest_ip LIKE {ippfx:String})"

    # ── General text search (username, URL, hostname, category) ──
    params["q"] = f"%{term}%"
    # Check if term contains non-ASCII (Arabic, etc.) — need to match against decoded URL
    has_non_ascii = any(ord(c) > 127 for c in term)
    # Also try with spaces→+ for URL query string matching
    has_spaces = ' ' in term

    url_match = "url ILIKE {q:String}"
    if has_non_ascii:
        # Match against URL-decoded version for non-ASCII text
        url_match = "decodeURLComponent(url) ILIKE {q:String}"
    if has_spaces:
        params["qplus"] = f"%{term.replace(' ', '+')}%"
        if has_non_ascii:
            url_match = (f"(decodeURLComponent(url) ILIKE {{q:String}} "
                         f"OR decodeURLComponent(url) ILIKE {{qplus:String}})")
        else:
            url_match = f"(url ILIKE {{q:String}} OR url ILIKE {{qplus:String}})"

    return (
        f"(src_user ILIKE {{q:String}} "
        f"OR src_ip ILIKE {{q:String}} OR dest_ip ILIKE {{q:String}} "
        f"OR {url_match} OR hostname ILIKE {{q:String}} "
        f"OR url_category ILIKE {{q:String}})"
    )


# ============================================================
# Fortinet UTM → UNION ALL helper
# ============================================================

# Columns selected from the Fortinet subquery, matching pa_threat_logs schema.
# Used by all endpoints that query pa_threat_logs.
_FORTI_LOG_TYPES = "('utm/webfilter', 'utm/dns', 'utm/virus', 'utm/ips')"


def _fortinet_select(hours: int, extra_where: str = "") -> str:
    """Return a SELECT … FROM syslogs that maps Fortinet UTM rows to
    the pa_threat_logs column schema.

    ``extra_where`` — additional AND clauses (already prefixed with AND).
    """
    return f"""
    SELECT
        timestamp,
        '' as receive_time,
        '' as generated_time,
        '' as serial_number,
        '' as device_name,
        parsed_data['vd'] as vsys,
        '' as vsys_name,
        device_ip,
        CASE log_type
            WHEN 'utm/webfilter' THEN 'url'
            WHEN 'utm/dns'       THEN 'spyware'
            WHEN 'utm/virus'     THEN 'virus'
            WHEN 'utm/ips'       THEN 'vulnerability'
            ELSE log_type
        END as log_subtype,
        multiIf(
            parsed_data['level'] IN ('emergency','alert','critical'), 'critical',
            parsed_data['level'] = 'error',   'high',
            parsed_data['level'] = 'warning', 'medium',
            parsed_data['level'] = 'notice',  'low',
            'informational'
        ) as severity,
        parsed_data['direction'] as direction,
        action,
        srcip  as src_ip,
        dstip  as dest_ip,
        srcport  as src_port,
        dstport  as dest_port,
        CASE parsed_data['proto']
            WHEN '6'  THEN 'tcp'
            WHEN '17' THEN 'udp'
            WHEN '1'  THEN 'icmp'
            ELSE parsed_data['proto']
        END as transport,
        parsed_data['srcintf'] as src_zone,
        parsed_data['dstintf'] as dest_zone,
        parsed_data['srcintf'] as src_interface,
        parsed_data['dstintf'] as dest_interface,
        coalesce(nullIf(parsed_data['user'],''), parsed_data['srcuser'], '') as src_user,
        parsed_data['dstuser'] as dest_user,
        coalesce(nullIf(parsed_data['app'],''), parsed_data['appcat'], '') as application,
        coalesce(nullIf(parsed_data['policyname'],''), parsed_data['policyid'], '') as rule,
        coalesce(nullIf(parsed_data['threatid'],''), parsed_data['attackid'], '') as threat_id,
        CASE log_type
            WHEN 'utm/webfilter' THEN coalesce(nullIf(parsed_data['msg'],''), parsed_data['catdesc'], '')
            WHEN 'utm/dns'       THEN coalesce(nullIf(parsed_data['qname'],''), parsed_data['hostname'], '')
            WHEN 'utm/virus'     THEN coalesce(nullIf(parsed_data['virus'],''), parsed_data['msg'], '')
            WHEN 'utm/ips'       THEN coalesce(nullIf(parsed_data['attack'],''), parsed_data['msg'], '')
            ELSE ''
        END as threat_name,
        CASE log_type
            WHEN 'utm/webfilter' THEN 'url'
            WHEN 'utm/dns'       THEN 'dns-malware'
            WHEN 'utm/virus'     THEN 'virus'
            WHEN 'utm/ips'       THEN coalesce(nullIf(parsed_data['attackid'],''), 'ips')
            ELSE ''
        END as threat_category,
        CASE log_type
            WHEN 'utm/webfilter' THEN coalesce(nullIf(parsed_data['catdesc'],''), parsed_data['urlcat'], '')
            WHEN 'utm/dns'       THEN coalesce(nullIf(parsed_data['catdesc'],''), 'dns')
            WHEN 'utm/virus'     THEN 'virus'
            WHEN 'utm/ips'       THEN 'vulnerability'
            ELSE ''
        END as category,
        CASE log_type
            WHEN 'utm/webfilter' THEN coalesce(nullIf(parsed_data['url'],''), parsed_data['hostname'], '')
            WHEN 'utm/dns'       THEN coalesce(nullIf(parsed_data['qname'],''), parsed_data['hostname'], '')
            ELSE ''
        END as url,
        parsed_data['contenttype'] as content_type,
        parsed_data['agent']       as user_agent,
        parsed_data['httpmethod']  as http_method,
        ''                         as xff,
        ''                         as xff_ip,
        parsed_data['referralurl'] as referrer,
        coalesce(nullIf(parsed_data['reason'],''), parsed_data['msg'], '') as reason,
        ''                         as justification,
        parsed_data['filename']    as file_name,
        parsed_data['filehash']    as file_hash,
        parsed_data['filetype']    as file_type,
        toUInt64OrZero(parsed_data['sessionid']) as session_id,
        parsed_data['srccountry']  as src_location,
        parsed_data['dstcountry']  as dest_location
    FROM syslogs
    WHERE timestamp > now() - INTERVAL {hours} HOUR
      AND log_type IN {_FORTI_LOG_TYPES}
      {extra_where}
    """


def _combined_cte(hours: int, pa_extra: str = "", forti_extra: str = "",
                  pa_cols: str = "*", forti_cols: str | None = None) -> str:
    """Build ``WITH combined AS (… UNION ALL …)`` CTE.

    ``pa_cols`` / ``forti_cols`` — column list for the inner selects.
    If ``forti_cols`` is None it mirrors ``pa_cols``.
    ``pa_extra`` / ``forti_extra`` — extra AND-clauses.
    """
    if forti_cols is None:
        forti_cols = pa_cols
    pa_part = f"""
        SELECT {pa_cols}
        FROM pa_threat_logs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          {pa_extra}
    """
    forti_part = _fortinet_select(hours, forti_extra)
    # When pa_cols != "*" we need to wrap the fortinet select to project
    # the same columns. If pa_cols == "*" we use the full fortinet select.
    if pa_cols != "*":
        # Wrap fortinet subquery to select matching columns
        forti_part = f"SELECT {forti_cols} FROM ({forti_part}) _f"

    return f"WITH combined AS (\n{pa_part}\nUNION ALL\n{forti_part}\n)"


# ============================================================
# Dashboard Page
# ============================================================

@router.get("/threats/", response_class=HTMLResponse, name="threat_dashboard",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_dashboard_page(request: Request):
    """Threat & URL filtering dashboard page."""
    return _render("threats/dashboard.html", request)


# ============================================================
# JSON API — Summary Stats
# ============================================================

@router.get("/api/threats/summary", name="api_threat_summary",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_summary(
    hours: int = Query(24, ge=1, le=720),
):
    """Summary metrics for the threat dashboard hero cards."""
    try:
        client = ClickHouseClient.get_client()
        cte = _combined_cte(hours,
                            pa_cols="severity, log_subtype, src_ip, threat_name",
                            forti_cols="severity, log_subtype, src_ip, threat_name")

        # Total threat events in window
        total_q = f"{cte} SELECT count() as total FROM combined"
        total = client.query(total_q).result_rows
        total_count = _safe(total[0][0]) if total else 0

        # By severity
        sev_q = f"{cte} SELECT severity, count() as cnt FROM combined GROUP BY severity"
        sev_rows = client.query(sev_q).result_rows
        sev_map = {r[0].lower(): _safe(r[1]) for r in sev_rows}

        # By subtype
        sub_q = f"{cte} SELECT log_subtype, count() as cnt FROM combined GROUP BY log_subtype ORDER BY cnt DESC"
        sub_rows = client.query(sub_q).result_rows

        # Unique source IPs
        src_q = f"{cte} SELECT uniqExact(src_ip) as u FROM combined"
        src = client.query(src_q).result_rows
        unique_sources = _safe(src[0][0]) if src else 0

        # Unique threats
        thr_q = f"{cte} SELECT uniqExact(threat_name) as u FROM combined WHERE threat_name != ''"
        thr = client.query(thr_q).result_rows
        unique_threats = _safe(thr[0][0]) if thr else 0

        # URL filtering count
        url_count = 0
        for r in sub_rows:
            if r[0] == 'url':
                url_count = _safe(r[1])
                break

        return JSONResponse({
            "success": True,
            "hours": hours,
            "total": total_count,
            "severity": {
                "critical": sev_map.get("critical", 0),
                "high": sev_map.get("high", 0),
                "medium": sev_map.get("medium", 0),
                "low": sev_map.get("low", 0),
                "informational": sev_map.get("informational", 0),
            },
            "subtypes": [{"name": r[0], "count": _safe(r[1])} for r in sub_rows],
            "unique_sources": unique_sources,
            "unique_threats": unique_threats,
            "url_filtering_count": url_count,
        })
    except Exception as e:
        logger.error(f"Threat summary error: {e}")
        return JSONResponse({
            "success": True,
            "hours": hours,
            "total": 0,
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
            "subtypes": [],
            "unique_sources": 0,
            "unique_threats": 0,
            "url_filtering_count": 0,
        })


# ============================================================
# JSON API — Recent Threat Events
# ============================================================

@router.get("/api/threats/events", name="api_threat_events",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_events(
    hours: int = Query(24, ge=1, le=720),
    severity: Optional[str] = None,
    subtype: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    action: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List recent threat events with filters."""
    try:
        client = ClickHouseClient.get_client()

        where = []
        params = {}

        if severity:
            where.append("severity = {sev:String}")
            params["sev"] = severity
        if subtype:
            where.append("log_subtype = {sub:String}")
            params["sub"] = subtype
        if src_ip:
            where.append("src_ip = {sip:String}")
            params["sip"] = src_ip
        if dest_ip:
            where.append("dest_ip = {dip:String}")
            params["dip"] = dest_ip
        if action:
            where.append("action = {act:String}")
            params["act"] = action
        if search:
            where.append("(threat_name ILIKE {q:String} OR url ILIKE {q:String} OR src_ip ILIKE {q:String} OR dest_ip ILIKE {q:String})")
            params["q"] = f"%{search}%"

        outer_where = (" AND " + " AND ".join(where)) if where else ""

        _cols = """timestamp, log_subtype, severity, action,
            src_ip, dest_ip, src_port, dest_port, transport,
            src_zone, dest_zone,
            application, rule, src_user,
            threat_id, threat_name, threat_category, category,
            url, file_name, file_hash,
            direction, device_name, device_ip,
            session_id"""
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)

        # Count
        count_q = f"{cte} SELECT count() FROM combined WHERE 1=1 {outer_where}"
        count_result = client.query(count_q, parameters=params).result_rows
        total = _safe(count_result[0][0]) if count_result else 0

        # Fetch rows
        query = f"""
        {cte}
        SELECT *
        FROM combined
        WHERE 1=1 {outer_where}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """
        rows = client.query(query, parameters=params).named_results()

        events = []
        for r in rows:
            ts = r['timestamp']
            events.append({
                "timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                "subtype": r['log_subtype'],
                "severity": r['severity'],
                "action": r['action'],
                "src_ip": r['src_ip'],
                "dest_ip": r['dest_ip'],
                "src_port": r['src_port'],
                "dest_port": r['dest_port'],
                "transport": r['transport'],
                "src_zone": r['src_zone'],
                "dest_zone": r['dest_zone'],
                "application": r['application'],
                "rule": r['rule'],
                "src_user": r['src_user'],
                "threat_id": r['threat_id'],
                "threat_name": r['threat_name'],
                "threat_category": r['threat_category'],
                "category": r['category'],
                "url": r['url'],
                "file_name": r['file_name'],
                "file_hash": r['file_hash'],
                "direction": r['direction'],
                "device_name": r['device_name'],
                "device_ip": r['device_ip'],
                "session_id": r['session_id'],
            })

        return JSONResponse({
            "success": True,
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": events,
        })
    except Exception as e:
        logger.error(f"Threat events error: {e}")
        return JSONResponse({"success": True, "total": 0, "events": []})


# ============================================================
# JSON API — Top Attackers
# ============================================================

@router.get("/api/threats/top-sources", name="api_threat_top_sources",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_top_sources(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(15, ge=1, le=50),
):
    """Top source IPs generating threat events."""
    try:
        client = ClickHouseClient.get_client()
        _cols = "src_ip, dest_ip, threat_name, severity, action, src_user"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)
        query = f"""
        {cte}
        SELECT
            src_ip,
            count() as event_count,
            uniqExact(threat_name) as unique_threats,
            uniqExact(dest_ip) as targets,
            countIf(severity IN ('critical', 'high')) as critical_high,
            countIf(action IN ('block-url', 'deny', 'drop', 'sinkhole', 'reset-client', 'reset-server')) as blocked,
            groupArray(10)(DISTINCT severity) as severities,
            any(src_user) as src_user
        FROM combined
        WHERE src_ip != ''
        GROUP BY src_ip
        ORDER BY event_count DESC
        LIMIT {limit}
        """
        rows = list(client.query(query).named_results())
        sources = []
        for r in rows:
            sources.append({
                "src_ip": r['src_ip'],
                "event_count": _safe(r['event_count']),
                "unique_threats": _safe(r['unique_threats']),
                "targets": _safe(r['targets']),
                "critical_high": _safe(r['critical_high']),
                "blocked": _safe(r['blocked']),
                "severities": r.get('severities', []),
                "src_user": r.get('src_user') or "",
            })
        return JSONResponse({"success": True, "sources": sources})
    except Exception as e:
        logger.error(f"Top sources error: {e}")
        return JSONResponse({"success": True, "sources": []})


# ============================================================
# JSON API — Source IP Drill-Down
# ============================================================

@router.get("/api/threats/source-detail", name="api_source_detail",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_source_detail(
    src_ip: str = Query(...),
    hours: int = Query(24, ge=1, le=720),
):
    """Detailed drill-down for a specific source IP."""
    try:
        client = ClickHouseClient.get_client()
        params = {"sip": src_ip}
        _cols = "timestamp, src_ip, dest_ip, threat_name, log_subtype, severity, action, src_user"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)

        summary_q = f"""
        {cte}
        SELECT
            count() as total,
            uniqExact(threat_name) as unique_threats,
            uniqExact(dest_ip) as unique_targets,
            uniqExact(log_subtype) as unique_subtypes,
            countIf(severity IN ('critical', 'high')) as critical_high,
            countIf(action IN ('block-url', 'deny', 'drop', 'sinkhole', 'reset-client', 'reset-server')) as blocked,
            any(src_user) as src_user
        FROM combined
        WHERE src_ip = {{sip:String}}
        """
        sr = list(client.query(summary_q, parameters=params).named_results())
        s = sr[0] if sr else {}
        summary = {
            "total": _safe(s.get('total')),
            "unique_threats": _safe(s.get('unique_threats')),
            "unique_targets": _safe(s.get('unique_targets')),
            "unique_subtypes": _safe(s.get('unique_subtypes')),
            "critical_high": _safe(s.get('critical_high')),
            "blocked": _safe(s.get('blocked')),
            "src_user": s.get('src_user') or "",
        }

        # Top threats from this source
        threats_q = f"""
        {cte}
        SELECT threat_name, count() as cnt, any(severity) as sev, any(action) as act
        FROM combined
        WHERE src_ip = {{sip:String}} AND threat_name != ''
        GROUP BY threat_name ORDER BY cnt DESC LIMIT 10
        """
        tr = list(client.query(threats_q, parameters=params).named_results())
        top_threats = [{"threat_name": r['threat_name'], "count": _safe(r['cnt']),
                        "severity": r['sev'], "action": r['act']} for r in tr]

        # Top targets
        targets_q = f"""
        {cte}
        SELECT dest_ip, count() as cnt, uniqExact(threat_name) as threats, any(action) as act
        FROM combined
        WHERE src_ip = {{sip:String}}
        GROUP BY dest_ip ORDER BY cnt DESC LIMIT 10
        """
        tg = list(client.query(targets_q, parameters=params).named_results())
        top_targets = [{"dest_ip": r['dest_ip'], "count": _safe(r['cnt']),
                        "threats": _safe(r['threats']), "action": r['act']} for r in tg]

        # Subtype breakdown
        subtype_q = f"""
        {cte}
        SELECT log_subtype, count() as cnt
        FROM combined
        WHERE src_ip = {{sip:String}}
        GROUP BY log_subtype ORDER BY cnt DESC
        """
        st = list(client.query(subtype_q, parameters=params).named_results())
        subtypes = [{"subtype": r['log_subtype'], "count": _safe(r['cnt'])} for r in st]

        # Severity breakdown
        sev_q = f"""
        {cte}
        SELECT severity, count() as cnt
        FROM combined
        WHERE src_ip = {{sip:String}}
        GROUP BY severity ORDER BY cnt DESC
        """
        sv = list(client.query(sev_q, parameters=params).named_results())
        severities = [{"severity": r['severity'], "count": _safe(r['cnt'])} for r in sv]

        # Timeline
        tl_q = f"""
        {cte}
        SELECT toStartOfHour(timestamp) as hour, count() as total,
               countIf(severity IN ('critical', 'high')) as critical_high
        FROM combined
        WHERE src_ip = {{sip:String}}
        GROUP BY hour ORDER BY hour
        """
        tl = list(client.query(tl_q, parameters=params).named_results())
        timeline = [{"hour": r['hour'].isoformat() if hasattr(r['hour'], 'isoformat') else str(r['hour']),
                      "total": _safe(r['total']), "critical_high": _safe(r['critical_high'])} for r in tl]

        return JSONResponse({
            "success": True, "src_ip": src_ip, "hours": hours,
            "summary": summary, "top_threats": top_threats, "top_targets": top_targets,
            "subtypes": subtypes, "severities": severities, "timeline": timeline,
        })
    except Exception as e:
        logger.error(f"Source detail error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# JSON API — Top Threats
# ============================================================

@router.get("/api/threats/top-threats", name="api_threat_top_threats",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_top_threats(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(15, ge=1, le=50),
):
    """Top threat signatures seen."""
    try:
        client = ClickHouseClient.get_client()
        _cols = "threat_name, threat_category, src_ip, dest_ip, severity, action, log_subtype"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)
        query = f"""
        {cte}
        SELECT
            threat_name,
            threat_category,
            count() as event_count,
            uniqExact(src_ip) as unique_sources,
            uniqExact(dest_ip) as unique_targets,
            any(severity) as top_severity,
            any(action) as sample_action,
            any(log_subtype) as subtype
        FROM combined
        WHERE threat_name != ''
        GROUP BY threat_name, threat_category
        ORDER BY event_count DESC
        LIMIT {limit}
        """
        rows = list(client.query(query).named_results())
        threats = []
        for r in rows:
            threats.append({
                "threat_name": r['threat_name'],
                "threat_category": r['threat_category'],
                "event_count": _safe(r['event_count']),
                "unique_sources": _safe(r['unique_sources']),
                "unique_targets": _safe(r['unique_targets']),
                "severity": r['top_severity'],
                "action": r['sample_action'],
                "subtype": r.get('subtype', ''),
            })
        return JSONResponse({"success": True, "threats": threats})
    except Exception as e:
        logger.error(f"Top threats error: {e}")
        return JSONResponse({"success": True, "threats": []})


# ============================================================
# JSON API — Threat Signature Drill-Down
# ============================================================

@router.get("/api/threats/threat-sig-detail", name="api_threat_sig_detail",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_sig_detail(
    threat_name: str = Query(...),
    hours: int = Query(24, ge=1, le=720),
):
    """Detailed drill-down for a specific threat signature."""
    try:
        client = ClickHouseClient.get_client()
        params = {"tn": threat_name}
        _cols = "timestamp, src_ip, dest_ip, threat_name, threat_category, log_subtype, severity, action, src_user, rule"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)

        summary_q = f"""
        {cte}
        SELECT
            count() as total,
            uniqExact(src_ip) as unique_sources,
            uniqExact(dest_ip) as unique_targets,
            any(threat_category) as category,
            any(severity) as severity,
            any(log_subtype) as subtype,
            countIf(action IN ('block-url', 'deny', 'drop', 'sinkhole', 'reset-client', 'reset-server')) as blocked,
            countIf(action = 'alert') as alerted,
            countIf(action = 'allow') as allowed
        FROM combined
        WHERE threat_name = {{tn:String}}
        """
        sr = list(client.query(summary_q, parameters=params).named_results())
        s = sr[0] if sr else {}
        summary = {
            "total": _safe(s.get('total')),
            "unique_sources": _safe(s.get('unique_sources')),
            "unique_targets": _safe(s.get('unique_targets')),
            "category": s.get('category', ''),
            "severity": s.get('severity', ''),
            "subtype": s.get('subtype', ''),
            "blocked": _safe(s.get('blocked')),
            "alerted": _safe(s.get('alerted')),
            "allowed": _safe(s.get('allowed')),
        }

        # Top sources hitting this threat
        sources_q = f"""
        {cte}
        SELECT src_ip, src_user, count() as cnt, any(action) as act
        FROM combined
        WHERE threat_name = {{tn:String}}
        GROUP BY src_ip, src_user ORDER BY cnt DESC LIMIT 10
        """
        sc = list(client.query(sources_q, parameters=params).named_results())
        top_sources = [{"src_ip": r['src_ip'], "src_user": r['src_user'] or "",
                        "count": _safe(r['cnt']), "action": r['act']} for r in sc]

        # Top targets
        targets_q = f"""
        {cte}
        SELECT dest_ip, count() as cnt, any(action) as act
        FROM combined
        WHERE threat_name = {{tn:String}}
        GROUP BY dest_ip ORDER BY cnt DESC LIMIT 10
        """
        tg = list(client.query(targets_q, parameters=params).named_results())
        top_targets = [{"dest_ip": r['dest_ip'], "count": _safe(r['cnt']),
                        "action": r['act']} for r in tg]

        # Action breakdown
        action_q = f"""
        {cte}
        SELECT action, count() as cnt
        FROM combined
        WHERE threat_name = {{tn:String}}
        GROUP BY action ORDER BY cnt DESC
        """
        ac = list(client.query(action_q, parameters=params).named_results())
        actions = [{"action": r['action'], "count": _safe(r['cnt'])} for r in ac]

        # Top rules
        rules_q = f"""
        {cte}
        SELECT rule, count() as cnt
        FROM combined
        WHERE threat_name = {{tn:String}} AND rule != ''
        GROUP BY rule ORDER BY cnt DESC LIMIT 10
        """
        rl = list(client.query(rules_q, parameters=params).named_results())
        top_rules = [{"rule": r['rule'], "count": _safe(r['cnt'])} for r in rl]

        # Timeline
        tl_q = f"""
        {cte}
        SELECT toStartOfHour(timestamp) as hour, count() as total,
               countIf(action IN ('block-url', 'deny', 'drop', 'sinkhole')) as blocked
        FROM combined
        WHERE threat_name = {{tn:String}}
        GROUP BY hour ORDER BY hour
        """
        tl = list(client.query(tl_q, parameters=params).named_results())
        timeline = [{"hour": r['hour'].isoformat() if hasattr(r['hour'], 'isoformat') else str(r['hour']),
                      "total": _safe(r['total']), "blocked": _safe(r['blocked'])} for r in tl]

        return JSONResponse({
            "success": True, "threat_name": threat_name, "hours": hours,
            "summary": summary, "top_sources": top_sources, "top_targets": top_targets,
            "actions": actions, "top_rules": top_rules, "timeline": timeline,
        })
    except Exception as e:
        logger.error(f"Threat sig detail error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# JSON API — Timeline
# ============================================================

@router.get("/api/threats/timeline", name="api_threat_timeline",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_timeline(
    hours: int = Query(24, ge=1, le=720),
):
    """Threat events per hour for sparkline/chart."""
    try:
        client = ClickHouseClient.get_client()
        _cols = "timestamp, severity, log_subtype"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)
        query = f"""
        {cte}
        SELECT
            toStartOfHour(timestamp) as hour,
            count() as total,
            countIf(severity IN ('critical', 'high')) as critical_high,
            countIf(log_subtype = 'url') as url_events
        FROM combined
        GROUP BY hour
        ORDER BY hour
        """
        rows = list(client.query(query).named_results())
        timeline = []
        for r in rows:
            h = r['hour']
            timeline.append({
                "hour": h.isoformat() if hasattr(h, 'isoformat') else str(h),
                "total": _safe(r['total']),
                "critical_high": _safe(r['critical_high']),
                "url_events": _safe(r['url_events']),
            })
        return JSONResponse({"success": True, "timeline": timeline})
    except Exception as e:
        logger.error(f"Timeline error: {e}")
        return JSONResponse({"success": True, "timeline": []})


# ============================================================
# JSON API — URL Categories Breakdown
# ============================================================

@router.get("/api/threats/url-categories", name="api_threat_url_categories",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_url_categories(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(20, ge=1, le=50),
):
    """URL category breakdown for URL filtering subtype."""
    try:
        client = ClickHouseClient.get_client()
        _cols = "category, src_ip, action, log_subtype"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)
        query = f"""
        {cte}
        SELECT
            category,
            count() as event_count,
            uniqExact(src_ip) as unique_users,
            countIf(action IN ('block-url', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both')) as blocked,
            countIf(action = 'alert') as alerted,
            countIf(action = 'allow') as allowed,
            any(action) as sample_action
        FROM combined
        WHERE log_subtype = 'url'
          AND category != ''
        GROUP BY category
        ORDER BY event_count DESC
        LIMIT {limit}
        """
        rows = list(client.query(query).named_results())
        categories = []
        for r in rows:
            categories.append({
                "category": r['category'],
                "event_count": _safe(r['event_count']),
                "unique_users": _safe(r['unique_users']),
                "blocked": _safe(r['blocked']),
                "alerted": _safe(r['alerted']),
                "allowed": _safe(r['allowed']),
                "action": r['sample_action'],
            })
        return JSONResponse({"success": True, "categories": categories})
    except Exception as e:
        logger.error(f"URL categories error: {e}")
        return JSONResponse({"success": True, "categories": []})


# ============================================================
# JSON API — URL Category Drill-Down
# ============================================================

@router.get("/api/threats/url-category-detail", name="api_url_category_detail",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_url_category_detail(
    category: str = Query(...),
    hours: int = Query(24, ge=1, le=720),
):
    """Detailed drill-down for a specific URL category (from url_logs table)."""
    try:
        client = ClickHouseClient.get_client()
        params: dict = {"cat": category, "h": hours}

        tw = "timestamp > now() - INTERVAL {h:UInt32} HOUR AND url_category = {cat:String}"

        summary_q = f"""
        SELECT count() as total, uniqExact(src_ip) as unique_users,
               uniqExact(dest_ip) as unique_destinations, uniqExact(url) as unique_urls,
               countIf(action IN ('block-url','blocked','deny','drop','reset-client','reset-server')) as blocked,
               countIf(action = 'alert') as alerted,
               countIf(action IN ('allow','passthrough')) as allowed
        FROM url_logs WHERE {tw}
        """
        summary_rows = list(client.query(summary_q, parameters=params).named_results())
        summary = {}
        if summary_rows:
            s = summary_rows[0]
            summary = {k: _safe(s.get(k)) for k in
                       ('total','unique_users','unique_destinations','unique_urls','blocked','alerted','allowed')}

        urls_q = f"SELECT url, count() as hits, uniqExact(src_ip) as users, any(action) as action FROM url_logs WHERE {tw} AND url != '' GROUP BY url ORDER BY hits DESC LIMIT 15"
        top_urls = [{"url": r['url'], "hits": _safe(r['hits']), "users": _safe(r['users']), "action": r['action']}
                    for r in client.query(urls_q, parameters=params).named_results()]

        users_q = f"SELECT src_ip, any(src_user) as src_user, count() as hits, uniqExact(url) as urls_visited, countIf(action IN ('block-url','blocked','deny','drop')) as blocked FROM url_logs WHERE {tw} GROUP BY src_ip ORDER BY hits DESC LIMIT 10"
        top_users = [{"src_ip": r['src_ip'], "src_user": r['src_user'] or "", "hits": _safe(r['hits']),
                      "urls_visited": _safe(r['urls_visited']), "blocked": _safe(r['blocked'])}
                     for r in client.query(users_q, parameters=params).named_results()]

        dest_q = f"SELECT dest_ip, count() as hits, uniqExact(url) as unique_urls, any(action) as action FROM url_logs WHERE {tw} GROUP BY dest_ip ORDER BY hits DESC LIMIT 10"
        top_dests = [{"dest_ip": r['dest_ip'], "hits": _safe(r['hits']), "unique_urls": _safe(r['unique_urls']), "action": r['action']}
                     for r in client.query(dest_q, parameters=params).named_results()]

        timeline_q = f"SELECT toStartOfHour(timestamp) as hour, count() as total, countIf(action IN ('block-url','blocked','deny','drop')) as blocked FROM url_logs WHERE {tw} GROUP BY hour ORDER BY hour"
        timeline = [{"hour": r['hour'].isoformat() if hasattr(r['hour'], 'isoformat') else str(r['hour']),
                      "total": _safe(r['total']), "blocked": _safe(r['blocked'])}
                    for r in client.query(timeline_q, parameters=params).named_results()]

        action_q = f"SELECT action, count() as cnt FROM url_logs WHERE {tw} GROUP BY action ORDER BY cnt DESC"
        actions = [{"action": r['action'], "count": _safe(r['cnt'])}
                   for r in client.query(action_q, parameters=params).named_results()]

        return JSONResponse({
            "success": True, "category": category, "hours": hours,
            "summary": summary, "top_urls": top_urls, "top_users": top_users,
            "top_destinations": top_dests, "timeline": timeline, "actions": actions,
        })
    except Exception as e:
        logger.error(f"URL category detail error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# JSON API — Single Threat Detail
# ============================================================

@router.get("/api/threats/detail", name="api_threat_detail",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_threat_detail(
    timestamp: str = Query(...),
    device_ip: str = Query(...),
    session_id: int = Query(0),
):
    """Full detail of a single threat event."""
    try:
        client = ClickHouseClient.get_client()

        clean_ts = timestamp.replace('T', ' ').replace('Z', '')
        if '.' in clean_ts:
            parts = clean_ts.split('.')
            if len(parts[1]) > 3:
                clean_ts = parts[0] + '.' + parts[1][:3]

        query = """
        SELECT *
        FROM pa_threat_logs
        WHERE device_ip = {dip:String}
          AND timestamp >= toDateTime64('{ts}', 3) - INTERVAL 1 SECOND
          AND timestamp <= toDateTime64('{ts}', 3) + INTERVAL 1 SECOND
        ORDER BY timestamp
        LIMIT 1
        """.replace("{ts}", clean_ts)

        rows = list(client.query(query, parameters={"dip": device_ip}).named_results())
        if not rows:
            return JSONResponse({"success": False, "error": "Not found"}, status_code=404)

        row = rows[0]
        detail = {}
        for key, val in row.items():
            if hasattr(val, 'isoformat'):
                detail[key] = val.isoformat()
            else:
                detail[key] = val

        return JSONResponse({"success": True, "detail": detail})
    except Exception as e:
        logger.error(f"Threat detail error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# URL & DNS Log Viewer — Page
# ============================================================

@router.get("/threats/url-dns/", response_class=HTMLResponse, name="url_dns_logs",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def url_dns_logs_page(request: Request):
    """URL filtering & DNS traffic log viewer."""
    return _render("threats/url_dns_logs.html", request)


# ============================================================
# JSON API — URL Logs (from unified url_logs table)
# ============================================================

@router.get("/api/threats/url-logs", name="api_url_logs",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_url_logs(
    hours: int = Query(24, ge=1, le=720),
    category: Optional[str] = None,
    action: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    src_user: Optional[str] = None,
    http_method: Optional[str] = None,
    vendor: Optional[str] = None,
    search: Optional[str] = None,
    clean: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated URL filtering logs from the unified url_logs table."""
    try:
        client = ClickHouseClient.get_client()
        filters = ["timestamp > now() - INTERVAL {h:UInt32} HOUR"]
        params: dict = {"h": hours}

        if category:
            filters.append("url_category = {cat:String}")
            params["cat"] = category
        if action:
            filters.append("action = {act:String}")
            params["act"] = action
        if src_ip:
            filters.append("src_ip = {sip:String}")
            params["sip"] = src_ip
        if dest_ip:
            filters.append("dest_ip = {dip:String}")
            params["dip"] = dest_ip
        if src_user:
            filters.append("src_user ILIKE {su:String}")
            params["su"] = f"%{src_user}%"
        if http_method:
            filters.append("http_method = {hm:String}")
            params["hm"] = http_method
        if vendor:
            filters.append("vendor = {vnd:String}")
            params["vnd"] = vendor
        if search:
            filters.append(_build_url_search_clause(search, params))

        where = " AND ".join(filters)

        # SiteClean noise filtering
        if clean:
            from ..services.siteclean import build_siteclean_where
            sc = await build_siteclean_where()
            if sc:
                where += " " + sc

        count_q = f"SELECT count() FROM url_logs WHERE {where}"
        total = _safe((client.query(count_q, parameters=params).result_rows or [[0]])[0][0])

        query = f"""
        SELECT
            timestamp, vendor, src_ip, src_user, dest_ip, dest_port,
            url, hostname, url_category, action, http_method,
            user_agent, content_type, referrer,
            application, policy, severity,
            device_name, device_ip, session_id,
            msg, src_zone, dest_zone,
            src_country, dest_country,
            sent_bytes, recv_bytes, service,
            direction, profile, event_type, request_type
        FROM url_logs
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
        WHERE {where}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """
        rows = list(client.query(query, parameters=params).named_results())
        events = []
        for r in rows:
            ts = r['timestamp']
            events.append({
                "timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                "vendor": r['vendor'],
                "src_ip": r['src_ip'],
                "src_user": r['src_user'] or "",
                "dest_ip": r['dest_ip'],
                "dest_port": r['dest_port'],
                "url": r['url'],
                "hostname": r['hostname'] or "",
                "category": r['url_category'],
                "action": r['action'],
                "http_method": r['http_method'],
                "user_agent": r['user_agent'],
                "content_type": r['content_type'],
                "referrer": r['referrer'],
                "application": r['application'],
                "rule": r['policy'],
                "severity": r['severity'],
                "device_name": r['device_name'],
                "device_ip": r['device_ip'],
                "session_id": r['session_id'],
                "reason": r.get('msg') or "",
                "src_zone": r['src_zone'],
                "dest_zone": r['dest_zone'],
                "src_country": r['src_country'] or "",
                "dest_country": r['dest_country'] or "",
                "sent_bytes": r['sent_bytes'],
                "recv_bytes": r['recv_bytes'],
                "service": r['service'] or "",
                "direction": r['direction'] or "",
                "profile": r['profile'] or "",
                "event_type": r['event_type'] or "",
                "request_type": r['request_type'] or "",
            })

        return JSONResponse({
            "success": True, "total": total,
            "limit": limit, "offset": offset, "events": events,
        })
    except Exception as e:
        logger.error(f"URL logs error: {e}")
        return JSONResponse({"success": True, "total": 0, "events": []})


@router.get("/api/threats/url-logs/stats", name="api_url_logs_stats",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_url_logs_stats(
    hours: int = Query(24, ge=1, le=720),
    vendor: Optional[str] = None,
    category: Optional[str] = None,
    action: Optional[str] = None,
    search: Optional[str] = None,
    clean: bool = Query(False),
):
    """Stats for URL filtering logs from the unified url_logs table."""
    try:
        client = ClickHouseClient.get_client()
        tw = f"timestamp > now() - INTERVAL {hours} HOUR"
        params: dict = {}
        if vendor and vendor in ('fortinet', 'paloalto'):
            tw += " AND vendor = {vnd:String}"
            params["vnd"] = vendor
        if category:
            tw += " AND url_category = {cat:String}"
            params["cat"] = category
        if action:
            tw += " AND action = {act:String}"
            params["act"] = action
        if search:
            tw += " AND " + _build_url_search_clause(search, params)

        # SiteClean noise filtering
        if clean:
            from ..services.siteclean import build_siteclean_where
            sc = await build_siteclean_where()
            if sc:
                tw += " " + sc

        # Summary
        sum_q = f"""
        SELECT count() as total,
               uniqExact(src_ip) as unique_users,
               uniqExact(url) as unique_urls,
               uniqExact(url_category) as unique_categories,
               countIf(action IN ('block-url','blocked','deny','drop','reset-client','reset-server')) as blocked,
               countIf(action = 'alert') as alerted,
               countIf(action IN ('allow','passthrough')) as allowed,
               countIf(vendor = 'fortinet') as fortinet_count,
               countIf(vendor = 'paloalto') as paloalto_count
        FROM url_logs WHERE {tw}
        """
        sr = list(client.query(sum_q, parameters=params).named_results())
        s = sr[0] if sr else {}
        summary = {
            "total": _safe(s.get('total')),
            "unique_users": _safe(s.get('unique_users')),
            "unique_urls": _safe(s.get('unique_urls')),
            "unique_categories": _safe(s.get('unique_categories')),
            "blocked": _safe(s.get('blocked')),
            "alerted": _safe(s.get('alerted')),
            "allowed": _safe(s.get('allowed')),
            "fortinet_count": _safe(s.get('fortinet_count')),
            "paloalto_count": _safe(s.get('paloalto_count')),
        }

        # Top categories
        cat_q = f"""
        SELECT url_category as category, count() as cnt
        FROM url_logs WHERE {tw} AND url_category != ''
        GROUP BY url_category ORDER BY cnt DESC LIMIT 10
        """
        cats = [{"category": r['category'], "count": _safe(r['cnt'])}
                for r in client.query(cat_q, parameters=params).named_results()]

        # Top users
        usr_q = f"""
        SELECT src_ip, any(src_user) as src_user, count() as cnt
        FROM url_logs WHERE {tw}
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """
        users = [{"src_ip": r['src_ip'], "src_user": r['src_user'] or "", "count": _safe(r['cnt'])}
                 for r in client.query(usr_q, parameters=params).named_results()]

        # Action breakdown
        act_q = f"""
        SELECT action, count() as cnt
        FROM url_logs WHERE {tw}
        GROUP BY action ORDER BY cnt DESC
        """
        actions = [{"action": r['action'], "count": _safe(r['cnt'])}
                   for r in client.query(act_q, parameters=params).named_results()]

        # Top hostnames
        host_q = f"""
        SELECT hostname, count() as cnt
        FROM url_logs WHERE {tw} AND hostname != ''
        GROUP BY hostname ORDER BY cnt DESC LIMIT 10
        """
        top_hostnames = [{"hostname": r['hostname'], "count": _safe(r['cnt'])}
                         for r in client.query(host_q, parameters=params).named_results()]

        # Available categories for filter dropdown
        fcat_q = f"""
        SELECT DISTINCT url_category as category FROM url_logs
        WHERE {tw} AND url_category != ''
        ORDER BY url_category LIMIT 100
        """
        filter_categories = [r['category'] for r in client.query(fcat_q, parameters=params).named_results()]

        return JSONResponse({
            "success": True, "summary": summary,
            "top_categories": cats, "top_users": users,
            "actions": actions, "top_hostnames": top_hostnames,
            "filter_categories": filter_categories,
        })
    except Exception as e:
        logger.error(f"URL logs stats error: {e}")
        return JSONResponse({"success": True, "summary": {}, "top_categories": [], "top_users": [], "actions": [], "top_hostnames": [], "filter_categories": []})


# ============================================================
# JSON API — DNS Traffic Logs
# ============================================================

@router.get("/api/threats/dns-logs", name="api_dns_logs",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_dns_logs(
    hours: int = Query(24, ge=1, le=720),
    severity: Optional[str] = None,
    action: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    threat_name: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated DNS traffic logs — spyware subtype entries that are DNS-related."""
    try:
        client = ClickHouseClient.get_client()
        filters = ["log_subtype = 'spyware'"]
        params = {}

        if severity:
            filters.append("severity = {sev:String}")
            params["sev"] = severity
        if action:
            filters.append("action = {act:String}")
            params["act"] = action
        if src_ip:
            filters.append("src_ip = {sip:String}")
            params["sip"] = src_ip
        if dest_ip:
            filters.append("dest_ip = {dip:String}")
            params["dip"] = dest_ip
        if threat_name:
            filters.append("threat_name = {tn:String}")
            params["tn"] = threat_name
        if search:
            filters.append(
                "(threat_name ILIKE {q:String} OR src_ip ILIKE {q:String} "
                "OR dest_ip ILIKE {q:String} OR application ILIKE {q:String} "
                "OR rule ILIKE {q:String} OR src_user ILIKE {q:String})"
            )
            params["q"] = f"%{search}%"

        outer_where = " AND ".join(filters)

        _cols = """timestamp, src_ip, src_user, dest_ip, dest_port,
            threat_name, threat_category, category,
            action, severity, application, rule,
            device_name, device_ip, session_id,
            direction, transport, src_zone, dest_zone,
            url, log_subtype"""
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)

        count_q = f"{cte} SELECT count() FROM combined WHERE {outer_where}"
        total = _safe((client.query(count_q, parameters=params).result_rows or [[0]])[0][0])

        query = f"""
        {cte}
        SELECT
            timestamp, src_ip, src_user, dest_ip, dest_port,
            threat_name, threat_category, category,
            action, severity, application, rule,
            device_name, device_ip, session_id,
            direction, transport, src_zone, dest_zone,
            url
        FROM combined
        WHERE {outer_where}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """
        rows = list(client.query(query, parameters=params).named_results())
        events = []
        for r in rows:
            ts = r['timestamp']
            # Extract queried domain from threat_name
            tn = r['threat_name']
            domain = ""
            if "generic:" in tn:
                domain = tn.split("generic:")[-1].rstrip(")")
            elif "Grayware:" in tn:
                domain = tn.split("Grayware:")[-1].rstrip(")")
            elif "Ransomware:" in tn:
                domain = tn.split("Ransomware:")[-1].rstrip(")")

            events.append({
                "timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                "src_ip": r['src_ip'],
                "src_user": r['src_user'] or "",
                "dest_ip": r['dest_ip'],
                "dest_port": r['dest_port'],
                "threat_name": tn,
                "domain": domain,
                "threat_category": r['threat_category'],
                "category": r['category'],
                "action": r['action'],
                "severity": r['severity'],
                "application": r['application'],
                "rule": r['rule'],
                "device_name": r['device_name'],
                "device_ip": r['device_ip'],
                "session_id": r['session_id'],
                "direction": r['direction'],
                "transport": r['transport'],
                "src_zone": r['src_zone'],
                "dest_zone": r['dest_zone'],
                "url": r['url'],
            })

        return JSONResponse({
            "success": True, "total": total,
            "limit": limit, "offset": offset, "events": events,
        })
    except Exception as e:
        logger.error(f"DNS logs error: {e}")
        return JSONResponse({"success": True, "total": 0, "events": []})


@router.get("/api/threats/dns-logs/stats", name="api_dns_logs_stats",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_dns_logs_stats(
    hours: int = Query(24, ge=1, le=720),
):
    """Stats for DNS traffic — top queried domains, sources, actions."""
    try:
        client = ClickHouseClient.get_client()
        _cols = "src_ip, src_user, dest_ip, threat_name, action, severity, log_subtype"
        cte = _combined_cte(hours, pa_cols=_cols, forti_cols=_cols)
        dns_filter = "log_subtype = 'spyware'"

        # Summary
        sum_q = f"""
        {cte}
        SELECT count() as total,
               uniqExact(src_ip) as unique_sources,
               uniqExact(threat_name) as unique_signatures,
               uniqExact(dest_ip) as unique_resolvers,
               countIf(action IN ('sinkhole','deny','drop','reset-client','reset-server')) as blocked,
               countIf(action = 'alert') as alerted,
               countIf(action = 'allow') as allowed,
               countIf(severity IN ('critical','high')) as critical_high
        FROM combined WHERE {dns_filter}
        """
        sr = list(client.query(sum_q).named_results())
        s = sr[0] if sr else {}
        summary = {
            "total": _safe(s.get('total')),
            "unique_sources": _safe(s.get('unique_sources')),
            "unique_signatures": _safe(s.get('unique_signatures')),
            "unique_resolvers": _safe(s.get('unique_resolvers')),
            "blocked": _safe(s.get('blocked')),
            "alerted": _safe(s.get('alerted')),
            "allowed": _safe(s.get('allowed')),
            "critical_high": _safe(s.get('critical_high')),
        }

        # Top queried domains (threat_name)
        dom_q = f"""
        {cte}
        SELECT threat_name, count() as cnt, any(severity) as sev, any(action) as act
        FROM combined WHERE {dns_filter} AND threat_name != ''
        GROUP BY threat_name ORDER BY cnt DESC LIMIT 10
        """
        domains = [{"threat_name": r['threat_name'], "count": _safe(r['cnt']),
                     "severity": r['sev'], "action": r['act']}
                   for r in client.query(dom_q).named_results()]

        # Top sources
        src_q = f"""
        {cte}
        SELECT src_ip, any(src_user) as src_user, count() as cnt,
               uniqExact(threat_name) as unique_domains,
               countIf(action IN ('sinkhole','deny','drop')) as blocked
        FROM combined WHERE {dns_filter}
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """
        sources = [{"src_ip": r['src_ip'], "src_user": r['src_user'] or "",
                     "count": _safe(r['cnt']), "unique_domains": _safe(r['unique_domains']),
                     "blocked": _safe(r['blocked'])}
                   for r in client.query(src_q).named_results()]

        # Action breakdown
        act_q = f"""
        {cte}
        SELECT action, count() as cnt
        FROM combined WHERE {dns_filter}
        GROUP BY action ORDER BY cnt DESC
        """
        actions = [{"action": r['action'], "count": _safe(r['cnt'])}
                   for r in client.query(act_q).named_results()]

        # Severity breakdown
        sev_q = f"""
        {cte}
        SELECT severity, count() as cnt
        FROM combined WHERE {dns_filter}
        GROUP BY severity ORDER BY cnt DESC
        """
        severities = [{"severity": r['severity'], "count": _safe(r['cnt'])}
                      for r in client.query(sev_q).named_results()]

        return JSONResponse({
            "success": True, "summary": summary,
            "top_domains": domains, "top_sources": sources,
            "actions": actions, "severities": severities,
        })
    except Exception as e:
        logger.error(f"DNS logs stats error: {e}")
        return JSONResponse({"success": True, "summary": {}, "top_domains": [], "top_sources": [], "actions": [], "severities": []})
