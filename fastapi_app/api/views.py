"""
HTML view routes for the web UI.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Optional
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..core.cache import get_redis
from ..models.device import Device, DeviceStatus, ParserType, RetentionDays
from ..models.credential import DeviceCredential, CredentialType, DeviceVdom
from ..models.device_ssh_settings import DeviceSshSettings
from ..models.routing import RoutingTableSnapshot, RoutingEntry, RouteChange
from ..models.zone import ZoneSnapshot, ZoneEntry, InterfaceEntry
from ..core.permissions import require_role, require_min_role

logger = logging.getLogger(__name__)

# Thread pool for running blocking ClickHouse queries in parallel
_executor = ThreadPoolExecutor(max_workers=8)

router = APIRouter(tags=["views"])

templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    """Build base template context with current user info."""
    from ..__version__ import __version__
    ctx = {"request": request, "app_version": __version__}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    # Alert count is set async in _render_async or defaults to 0
    ctx["unread_alert_count"] = getattr(request.state, "_alert_count", 0)
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    """Render template with base context (current_user, etc.) merged in."""
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


# Severity mapping
SEVERITY_MAP = {
    0: 'Emergency',
    1: 'Alert',
    2: 'Critical',
    3: 'Error',
    4: 'Warning',
    5: 'Notice',
    6: 'Info',
    7: 'Debug'
}


def format_bytes(size) -> str:
    """Format bytes to human readable string."""
    # Handle string input (convert to int)
    if isinstance(size, str):
        try:
            size = int(size) if size else 0
        except (ValueError, TypeError):
            return "0 B"
    elif size is None:
        return "0 B"

    size = int(size)
    if size < 1024:
        return f"{size} B"
    for unit in ['KB', 'MB', 'GB', 'TB']:
        size /= 1024.0
        if size < 1024.0:
            if size < 10:
                return f"{size:.2f} {unit}"
            elif size < 100:
                return f"{size:.1f} {unit}"
            else:
                return f"{size:.0f} {unit}"
    return f"{size:.1f} PB"


def format_number(num: int) -> str:
    """Format large numbers with commas."""
    return f"{num:,}"


def timesince(dt: datetime) -> str:
    """Return human-readable time since datetime."""
    if not dt:
        return "Never"
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    diff = now - dt
    seconds = int(diff.total_seconds())

    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        return f"{seconds // 60} minutes"
    elif seconds < 86400:
        return f"{seconds // 3600} hours"
    else:
        return f"{seconds // 86400} days"


# Add custom filters to templates
templates.env.filters['format_bytes'] = format_bytes
templates.env.filters['format_number'] = format_number
templates.env.filters['timesince'] = timesince


@router.get("/", response_class=HTMLResponse, name="home")
async def home(request: Request):
    """Redirect to dashboard."""
    return RedirectResponse(url="/dashboard/")


@router.get("/dashboard/", response_class=HTMLResponse, name="dashboard")
async def dashboard(request: Request):
    """Dashboard view — embeds cached data inline for instant render, falls back to JS fetch."""
    import json as _json
    # Check if this worker has cached dashboard data (non-blocking, no queries)
    cached = ClickHouseClient._dashboard_cache
    inline_json = ""
    if cached:
        try:
            # Build the same payload shape as the API endpoint
            stats = cached
            severity_data = []
            for item in stats.get('severity_breakdown', []):
                severity_data.append({
                    'name': SEVERITY_MAP.get(item.get('severity'), f"Level {item.get('severity')}"),
                    'count': _safe_int(item.get('count', 0)),
                    'severity': _safe_int(item.get('severity', 6))
                })
            timeline = {'labels': [], 'total': [], 'critical': [], 'denied': []}
            for item in stats.get('traffic_timeline', []):
                hour = item.get('hour')
                timeline['labels'].append(hour.strftime('%H:%M') if hasattr(hour, 'strftime') else str(hour))
                timeline['total'].append(_safe_int(item.get('total', 0)))
                timeline['critical'].append(_safe_int(item.get('critical', 0)))
                timeline['denied'].append(_safe_int(item.get('denied', 0)))
            realtime = {'labels': [], 'data': []}
            for item in stats.get('realtime_traffic', []):
                minute = item.get('minute')
                realtime['labels'].append(minute.strftime('%H:%M') if hasattr(minute, 'strftime') else str(minute))
                realtime['data'].append(_safe_int(item.get('count', 0)))
            actions = [{'action': str(a.get('action_type', '')), 'count': _safe_int(a.get('count', 0))} for a in stats.get('action_breakdown', [])]
            protocols = [{'protocol': str(p.get('protocol', '')), 'count': _safe_int(p.get('count', 0))} for p in stats.get('protocol_distribution', [])]
            top_sources = [{'ip': str(s.get('ip', '')), 'count': _safe_int(s.get('count', 0)), 'denied_count': _safe_int(s.get('denied_count', 0))} for s in stats.get('top_sources', [])]
            threats = [{'ip': str(t.get('ip', '')), 'denied_count': _safe_int(t.get('denied_count', 0)), 'unique_targets': _safe_int(t.get('unique_targets', 0)), 'unique_ports': _safe_int(t.get('unique_ports', 0))} for t in stats.get('potential_threats', [])]
            ports = [{'port': _safe_int(p.get('port', 0)), 'service': _PORT_SERVICES.get(_safe_int(p.get('port', 0)), '-'), 'count': _safe_int(p.get('count', 0)), 'denied_count': _safe_int(p.get('denied_count', 0))} for p in stats.get('top_ports', [])]
            devices = []
            for dv in stats.get('device_activity', []):
                ls = dv.get('last_seen')
                devices.append({
                    'device': str(dv.get('device', '')), 'log_count': _safe_int(dv.get('log_count', 0)),
                    'critical_count': _safe_int(dv.get('critical_count', 0)),
                    'last_seen': ls.isoformat() if hasattr(ls, 'isoformat') else str(ls) if ls else None,
                })
            recent_logs = []
            payload = _sanitize({
                'kpi': {
                    'total_24h': _safe_int(stats.get('total_logs_24h', 0)),
                    'avg_eps': round(float(stats.get('avg_eps', 0)), 1),
                    'current_eps': round(float(stats.get('current_eps', 0)), 1),
                    'allowed': _safe_int(stats.get('allowed_count', 0)),
                    'denied': _safe_int(stats.get('denied_count', 0)),
                    'critical': _safe_int(stats.get('critical_count', 0)),
                    'active_devices': _safe_int(stats.get('active_devices', 0)),
                    'url_total': 0, 'url_blocked': 0, 'dns_total': 0, 'dns_sinkholed': 0, 'dns_critical': 0,
                },
                'severity_data': severity_data, 'timeline': timeline, 'realtime': realtime,
                'actions': actions, 'protocols': protocols, 'top_sources': top_sources,
                'top_destinations': [], 'threats': threats, 'ports': ports,
                'devices': devices, 'recent_logs': recent_logs,
            })
            inline_json = _json.dumps(payload)
        except Exception:
            inline_json = ""
    return _render("logs/dashboard.html", request, {"inline_data": inline_json})


# Port service mapping (shared by API)
_PORT_SERVICES = {
    22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}


def _safe_int(v):
    """Convert ClickHouse numeric to int."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _sanitize(obj):
    """Recursively convert non-JSON-safe types in nested dicts/lists."""
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    if isinstance(obj, (IPv4Address, IPv6Address)):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    return obj


# Shared dashboard payload cache (Redis-backed so all uvicorn workers share it).
_DASHBOARD_API_CACHE_KEY = "dashboard:api:stats:v1"
_DASHBOARD_API_CACHE_TTL = 300        # serve fresh for 5 min
_DASHBOARD_API_STALE_TTL = 600        # serve stale up to 10 min while refreshing
_dashboard_api_refreshing = False     # in-process flag to dedupe refresh threads


async def _compute_dashboard_payload() -> dict:
    """Run all the dashboard queries and return the response payload."""
    loop = asyncio.get_event_loop()
    stats_future = loop.run_in_executor(_executor, ClickHouseClient.get_dashboard_stats)
    logs_future = loop.run_in_executor(_executor, lambda: ClickHouseClient.get_recent_logs(limit=15))

    def _get_url_dns_stats():
        try:
            client = ClickHouseClient.get_client()
            r = list(client.query("""
                WITH combined AS (
                    SELECT log_subtype, action, severity
                    FROM pa_threat_logs
                    WHERE timestamp > now() - INTERVAL 24 HOUR
                  UNION ALL
                    SELECT
                        CASE log_type
                            WHEN 'utm/webfilter' THEN 'url'
                            WHEN 'utm/dns'       THEN 'spyware'
                            WHEN 'utm/virus'     THEN 'virus'
                            WHEN 'utm/ips'       THEN 'vulnerability'
                            ELSE log_type
                        END as log_subtype,
                        action,
                        multiIf(
                            parsed_data['level'] IN ('emergency','alert','critical'), 'critical',
                            parsed_data['level'] = 'error',   'high',
                            parsed_data['level'] = 'warning', 'medium',
                            parsed_data['level'] = 'notice',  'low',
                            'informational'
                        ) as severity
                    FROM syslogs
                    WHERE timestamp > now() - INTERVAL 24 HOUR
                      AND log_type IN ('utm/webfilter', 'utm/dns', 'utm/virus', 'utm/ips')
                )
                SELECT
                    countIf(log_subtype = 'url') as url_total,
                    countIf(log_subtype = 'url' AND action IN ('block-url','deny','drop','reset-client','reset-server')) as url_blocked,
                    countIf(log_subtype = 'spyware') as dns_total,
                    countIf(log_subtype = 'spyware' AND action = 'sinkhole') as dns_sinkholed,
                    countIf(log_subtype = 'spyware' AND severity IN ('critical','high')) as dns_critical
                FROM combined
            """).named_results())
            if r:
                return {k: _safe_int(v) for k, v in r[0].items()}
            return {}
        except Exception:
            return {}

    url_dns_future = loop.run_in_executor(_executor, _get_url_dns_stats)
    stats, logs, url_dns = await asyncio.gather(stats_future, logs_future, url_dns_future)

    severity_data = []
    for item in stats.get('severity_breakdown', []):
        severity_data.append({
            'name': SEVERITY_MAP.get(item.get('severity'), f"Level {item.get('severity')}"),
            'count': _safe_int(item.get('count', 0)),
            'severity': _safe_int(item.get('severity', 6))
        })

    timeline = {'labels': [], 'total': [], 'critical': [], 'denied': []}
    for item in stats.get('traffic_timeline', []):
        hour = item.get('hour')
        timeline['labels'].append(hour.strftime('%H:%M') if hasattr(hour, 'strftime') else str(hour))
        timeline['total'].append(_safe_int(item.get('total', 0)))
        timeline['critical'].append(_safe_int(item.get('critical', 0)))
        timeline['denied'].append(_safe_int(item.get('denied', 0)))

    realtime = {'labels': [], 'data': []}
    for item in stats.get('realtime_traffic', []):
        minute = item.get('minute')
        realtime['labels'].append(minute.strftime('%H:%M') if hasattr(minute, 'strftime') else str(minute))
        realtime['data'].append(_safe_int(item.get('count', 0)))

    actions = [{'action': str(a.get('action_type', '')), 'count': _safe_int(a.get('count', 0))} for a in stats.get('action_breakdown', [])]
    protocols = [{'protocol': str(p.get('protocol', '')), 'count': _safe_int(p.get('count', 0))} for p in stats.get('protocol_distribution', [])]
    top_sources = [{'ip': str(s.get('ip', '')), 'count': _safe_int(s.get('count', 0)), 'denied_count': _safe_int(s.get('denied_count', 0))} for s in stats.get('top_sources', [])]
    top_dests = [{'ip': str(d.get('ip', '')), 'count': _safe_int(d.get('count', 0)), 'denied_count': _safe_int(d.get('denied_count', 0))} for d in stats.get('top_destinations', [])]
    threats = [{'ip': str(t.get('ip', '')), 'denied_count': _safe_int(t.get('denied_count', 0)), 'unique_targets': _safe_int(t.get('unique_targets', 0)), 'unique_ports': _safe_int(t.get('unique_ports', 0))} for t in stats.get('potential_threats', [])]
    ports = [{'port': _safe_int(p.get('port', 0)), 'service': _PORT_SERVICES.get(_safe_int(p.get('port', 0)), '-'), 'count': _safe_int(p.get('count', 0)), 'denied_count': _safe_int(p.get('denied_count', 0))} for p in stats.get('top_ports', [])]
    devices = []
    for dv in stats.get('device_activity', []):
        ls = dv.get('last_seen')
        devices.append({
            'device': str(dv.get('device', '')), 'log_count': _safe_int(dv.get('log_count', 0)),
            'critical_count': _safe_int(dv.get('critical_count', 0)),
            'last_seen': ls.isoformat() if hasattr(ls, 'isoformat') else str(ls) if ls else None,
        })

    recent = []
    for log in (logs or [])[:15]:
        ts = log.get('timestamp')
        sev = log.get('severity', 6)
        recent.append({
            'timestamp': ts.strftime('%H:%M:%S') if hasattr(ts, 'strftime') else str(ts) if ts else '-',
            'device_ip': log.get('device_ip', ''),
            'severity': sev,
            'severity_name': SEVERITY_MAP.get(sev, 'Unknown'),
            'message': (log.get('message', '') or '')[:150],
        })

    payload = {
        'kpi': {
            'total_24h': _safe_int(stats.get('total_logs_24h', 0)),
            'avg_eps': round(float(stats.get('avg_eps', 0)), 1),
            'current_eps': round(float(stats.get('current_eps', 0)), 1),
            'allowed': _safe_int(stats.get('allowed_count', 0)),
            'denied': _safe_int(stats.get('denied_count', 0)),
            'critical': _safe_int(stats.get('critical_count', 0)),
            'active_devices': _safe_int(stats.get('active_devices', 0)),
            'url_total': _safe_int(url_dns.get('url_total', 0)),
            'url_blocked': _safe_int(url_dns.get('url_blocked', 0)),
            'dns_total': _safe_int(url_dns.get('dns_total', 0)),
            'dns_sinkholed': _safe_int(url_dns.get('dns_sinkholed', 0)),
            'dns_critical': _safe_int(url_dns.get('dns_critical', 0)),
        },
        'severity_data': severity_data,
        'timeline': timeline,
        'realtime': realtime,
        'actions': actions,
        'protocols': protocols,
        'top_sources': top_sources,
        'top_destinations': top_dests,
        'threats': threats,
        'ports': ports,
        'devices': devices,
        'recent_logs': recent,
    }
    return _sanitize(payload)


async def _refresh_dashboard_cache_async():
    """Recompute the payload and store in Redis. Used as background refresh."""
    global _dashboard_api_refreshing
    try:
        payload = await _compute_dashboard_payload()
        try:
            redis = await get_redis()
            await redis.set(
                _DASHBOARD_API_CACHE_KEY,
                json.dumps(payload),
                ex=_DASHBOARD_API_STALE_TTL,
            )
            await redis.set(
                _DASHBOARD_API_CACHE_KEY + ":fresh_until",
                str(int(time.time()) + _DASHBOARD_API_CACHE_TTL),
                ex=_DASHBOARD_API_STALE_TTL,
            )
        except Exception as e:
            logger.warning(f"Dashboard cache write failed: {e}")
    finally:
        _dashboard_api_refreshing = False


@router.get("/api/dashboard/stats")
async def api_dashboard_stats():
    """JSON API for dashboard stats — called async after page load.

    Cached in Redis (shared across uvicorn workers). Stale-while-revalidate:
    serves cached data instantly and refreshes in the background once the
    fresh window expires, so the user never waits 12+s for the heavy
    ClickHouse aggregations to run.
    """
    global _dashboard_api_refreshing
    try:
        # Try the cache first.
        try:
            redis = await get_redis()
            cached = await redis.get(_DASHBOARD_API_CACHE_KEY)
            fresh_until_raw = await redis.get(_DASHBOARD_API_CACHE_KEY + ":fresh_until")
            if cached:
                now = time.time()
                fresh_until = int(fresh_until_raw) if fresh_until_raw else 0
                # Stale → kick off background refresh, return stale immediately.
                if now > fresh_until and not _dashboard_api_refreshing:
                    _dashboard_api_refreshing = True
                    asyncio.create_task(_refresh_dashboard_cache_async())
                return JSONResponse(json.loads(cached))
        except Exception as e:
            logger.warning(f"Dashboard cache read failed, recomputing: {e}")

        # No cache — compute synchronously and store.
        payload = await _compute_dashboard_payload()
        try:
            redis = await get_redis()
            await redis.set(
                _DASHBOARD_API_CACHE_KEY,
                json.dumps(payload),
                ex=_DASHBOARD_API_STALE_TTL,
            )
            await redis.set(
                _DASHBOARD_API_CACHE_KEY + ":fresh_until",
                str(int(time.time()) + _DASHBOARD_API_CACHE_TTL),
                ex=_DASHBOARD_API_STALE_TTL,
            )
        except Exception as e:
            logger.warning(f"Dashboard cache write failed: {e}")
        return JSONResponse(payload)
    except Exception as e:
        logger.error(f"Dashboard stats API error: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse({'error': str(e)}, status_code=500)


@router.get("/logs/", response_class=HTMLResponse, name="log_list")
async def log_list(
    request: Request,
    device: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
    page: Optional[str] = Query("1"),
    per_page: Optional[str] = Query("100"),
    # Network filter parameters
    srcip: Optional[str] = Query(None),
    dstip: Optional[str] = Query(None),
    srcport: Optional[str] = Query(None),
    dstport: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    # Policy & Security filters
    policyname: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    threat_id: Optional[str] = Query(None),
    # Traffic analysis filters
    application: Optional[str] = Query(None),
    session_end_reason: Optional[str] = Query(None),
    # Infrastructure filters
    src_zone: Optional[str] = Query(None),
    dst_zone: Optional[str] = Query(None),
    # Aggregate view parameters
    view: Optional[str] = Query(None),
    group_by: Optional[str] = Query(None),
    subnet_rollup: Optional[str] = Query(None),
):
    """Log list view with filtering."""
    try:
        # Parse page and per_page with defaults
        try:
            page_num = int(page) if page and page.strip() else 1
            page_num = max(1, page_num)
        except (ValueError, TypeError):
            page_num = 1

        try:
            per_page_num = int(per_page) if per_page and per_page.strip() else 100
            per_page_num = max(10, min(200, per_page_num))
        except (ValueError, TypeError):
            per_page_num = 100

        offset = (page_num - 1) * per_page_num

        # Handle empty strings and convert severity to int
        device_ips = [device] if device and device.strip() else None
        severity_int = None
        if severity and severity.strip():
            try:
                severity_int = int(severity)
            except ValueError:
                severity_int = None
        severities = [severity_int] if severity_int is not None else None

        # Parse datetime strings
        start_time = None
        end_time = None
        now = datetime.now(timezone.utc)

        # Default to 1 hour if no time range specified (for performance)
        default_time_range = '1h'
        effective_time_range = time_range.strip().lower() if time_range and time_range.strip() else default_time_range

        # Handle time_range parameter (e.g., 15m, 1h, 24h, 7d)
        if effective_time_range.endswith('m'):
            try:
                minutes = int(effective_time_range[:-1])
                start_time = now - timedelta(minutes=minutes)
            except ValueError:
                pass
        elif effective_time_range.endswith('h'):
            try:
                hours = int(effective_time_range[:-1])
                start_time = now - timedelta(hours=hours)
            except ValueError:
                pass
        elif effective_time_range.endswith('d'):
            try:
                days = int(effective_time_range[:-1])
                start_time = now - timedelta(days=days)
            except ValueError:
                pass

        # Override with explicit start/end if provided
        if start:
            try:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))
            except ValueError:
                pass
        if end:
            try:
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))
            except ValueError:
                pass

        # Build search query from direct filter parameters (srcip, dstip, dstport)
        search_parts = []

        def _fmt(field, val):
            """Quote values with spaces so the regex parser captures the full value."""
            return f'{field}:"{val}"' if ' ' in val else f'{field}:{val}'

        # Handle srcip parameter
        srcip_clean = srcip.strip() if srcip and srcip.strip() else None
        if srcip_clean:
            search_parts.append(_fmt("srcip", srcip_clean))

        # Handle dstip parameter
        dstip_clean = dstip.strip() if dstip and dstip.strip() else None
        if dstip_clean:
            search_parts.append(_fmt("dstip", dstip_clean))

        # Handle dstport parameter
        dstport_clean = dstport.strip() if dstport and dstport.strip() else None
        if dstport_clean:
            search_parts.append(_fmt("dstport", dstport_clean))

        # Handle policyname parameter
        policyname_clean = policyname.strip() if policyname and policyname.strip() else None
        if policyname_clean:
            search_parts.append(_fmt("policyname", policyname_clean))

        # Handle srcport parameter
        srcport_clean = srcport.strip() if srcport and srcport.strip() else None
        if srcport_clean:
            search_parts.append(_fmt("srcport", srcport_clean))

        # Handle protocol parameter
        protocol_clean = protocol.strip() if protocol and protocol.strip() else None
        if protocol_clean:
            search_parts.append(_fmt("proto", protocol_clean))

        # Handle log_type parameter
        log_type_clean = log_type.strip() if log_type and log_type.strip() else None
        if log_type_clean:
            search_parts.append(_fmt("log_type", log_type_clean))

        # Handle threat_id parameter
        threat_id_clean = threat_id.strip() if threat_id and threat_id.strip() else None
        if threat_id_clean:
            search_parts.append(_fmt("threat_id", threat_id_clean))

        # Handle application parameter
        application_clean = application.strip() if application and application.strip() else None
        if application_clean:
            search_parts.append(_fmt("application", application_clean))

        # Handle session_end_reason parameter
        session_end_reason_clean = session_end_reason.strip() if session_end_reason and session_end_reason.strip() else None
        if session_end_reason_clean:
            search_parts.append(_fmt("session_end_reason", session_end_reason_clean))

        # Handle src_zone parameter
        src_zone_clean = src_zone.strip() if src_zone and src_zone.strip() else None
        if src_zone_clean:
            search_parts.append(_fmt("src_zone", src_zone_clean))

        # Handle dst_zone parameter
        dst_zone_clean = dst_zone.strip() if dst_zone and dst_zone.strip() else None
        if dst_zone_clean:
            search_parts.append(_fmt("dst_zone", dst_zone_clean))

        # Combine with existing q parameter if present
        search_query = q or ""
        if search_parts:
            direct_filters = " ".join(search_parts)
            if search_query:
                search_query = f"{search_query} {direct_filters}"
            else:
                search_query = direct_filters

        if action:
            # Map action filter to search terms using pipe for OR logic
            action_terms = {
                'accept': 'action:accept|allow|pass|close|client-rst|server-rst',
                'deny': 'action:deny|drop|block|reject',
                'close': 'action:close|client-rst|server-rst',
                'timeout': 'action:timeout',
            }
            if action in action_terms:
                if search_query:
                    search_query = f"{search_query} {action_terms[action]}"
                else:
                    search_query = action_terms[action]

        # Determine if aggregate view
        is_aggregate = view and view.strip().lower() == 'aggregate'

        # Parse group_by fields (whitelist validated)
        allowed_group_fields = {'srcip', 'dstip', 'dstport'}
        if group_by and group_by.strip():
            group_fields = [f.strip() for f in group_by.split(',') if f.strip() in allowed_group_fields]
        else:
            group_fields = ['srcip', 'dstip', 'dstport']
        if not group_fields:
            group_fields = ['srcip', 'dstip', 'dstport']

        # Subnet rollup: group srcip by /24 subnet
        is_subnet_rollup = subnet_rollup and subnet_rollup.strip().lower() in ('1', 'true', 'on')

        # Run all ClickHouse queries in parallel for better performance
        loop = asyncio.get_event_loop()

        if is_aggregate:
            logs_future = loop.run_in_executor(
                _executor,
                lambda: ClickHouseClient.aggregate_logs(
                    group_by_fields=group_fields,
                    limit=per_page_num,
                    offset=offset,
                    device_ips=device_ips,
                    severities=severities,
                    start_time=start_time,
                    end_time=end_time,
                    query_text=search_query if search_query else None,
                    subnet_rollup=is_subnet_rollup,
                )
            )

            total_future = loop.run_in_executor(
                _executor,
                lambda: ClickHouseClient.count_aggregate_groups(
                    group_by_fields=group_fields,
                    device_ips=device_ips,
                    severities=severities,
                    start_time=start_time,
                    end_time=end_time,
                    query_text=search_query if search_query else None,
                    subnet_rollup=is_subnet_rollup,
                )
            )
        else:
            logs_future = loop.run_in_executor(
                _executor,
                lambda: ClickHouseClient.search_logs(
                    limit=per_page_num,
                    offset=offset,
                    device_ips=device_ips,
                    severities=severities,
                    start_time=start_time,
                    end_time=end_time,
                    query_text=search_query if search_query else None,
                )
            )

            total_future = loop.run_in_executor(
                _executor,
                lambda: ClickHouseClient.count_logs(
                    device_ips=device_ips,
                    severities=severities,
                    start_time=start_time,
                    end_time=end_time,
                    query_text=search_query if search_query else None,
                )
            )

        stats_future = loop.run_in_executor(
            _executor,
            lambda: ClickHouseClient.get_log_stats_summary(
                device_ips=device_ips,
                start_time=start_time,
                end_time=end_time,
                query_text=search_query if search_query else None,
            )
        )

        devices_future = loop.run_in_executor(
            _executor,
            ClickHouseClient.get_distinct_devices
        )

        # Wait for all queries to complete
        logs_or_agg, total, stats, devices = await asyncio.gather(
            logs_future, total_future, stats_future, devices_future
        )

        # Format count display
        is_approximate = False
        total_display = f"{total:,}"

        total_pages = (total + per_page_num - 1) // per_page_num if total > 0 else 1

        # Clean up filter values for template (handle empty strings)
        current_device = device if device and device.strip() else None
        current_action = action if action and action.strip() else None
        current_q = q if q and q.strip() else None

        context = {
            "severity_map": SEVERITY_MAP,
            "devices": devices,
            "total": total,
            "total_display": total_display,
            "is_approximate": is_approximate,
            "stats": stats,
            "page": page_num,
            "per_page": per_page_num,
            "total_pages": total_pages,
            "has_prev": page_num > 1,
            "has_next": page_num < total_pages,
            # Current filters
            "current_device": current_device,
            "current_severity": severity_int,
            "current_q": current_q,
            "current_action": current_action,
            "current_start": start,
            "current_end": end,
            "current_time_range": effective_time_range,
            # Network filter values
            "current_srcip": srcip_clean,
            "current_dstip": dstip_clean,
            "current_srcport": srcport_clean,
            "current_dstport": dstport_clean,
            "current_protocol": protocol_clean,
            # Policy & Security filter values
            "current_policyname": policyname_clean,
            "current_log_type": log_type_clean,
            "current_threat_id": threat_id_clean,
            # Traffic analysis filter values
            "current_application": application_clean,
            "current_session_end_reason": session_end_reason_clean,
            # Infrastructure filter values
            "current_src_zone": src_zone_clean,
            "current_dst_zone": dst_zone_clean,
            # Aggregate view
            "is_aggregate": is_aggregate,
            "current_view": 'aggregate' if is_aggregate else '',
            "current_group_by": ','.join(group_fields),
            "group_fields": group_fields,
            "is_subnet_rollup": is_subnet_rollup,
            "error": None,
        }

        if is_aggregate:
            context["logs"] = []
            context["agg_rows"] = logs_or_agg
        else:
            context["logs"] = logs_or_agg
            context["agg_rows"] = []

        return _render("logs/log_list.html", request, context)
    except Exception as e:
        import traceback
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in log_list view: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        print(f"ERROR in log_list: {type(e).__name__}: {e}")
        print(traceback.format_exc())
        return _render("logs/log_list.html", request, {
            "logs": [],
            "severity_map": SEVERITY_MAP,
            "devices": [],
            "total": 0,
            "total_display": "0",
            "is_approximate": False,
            "stats": {},
            "page": 1,
            "per_page": 100,
            "total_pages": 1,
            "has_prev": False,
            "has_next": False,
            "current_device": None,
            "current_severity": None,
            "current_q": None,
            "current_action": None,
            "current_start": start if start else None,
            "current_end": end if end else None,
            "current_time_range": time_range if time_range else '1h',
            # Network filter values
            "current_srcip": srcip if srcip else None,
            "current_dstip": dstip if dstip else None,
            "current_srcport": srcport if srcport else None,
            "current_dstport": dstport if dstport else None,
            "current_protocol": protocol if protocol else None,
            # Policy & Security filter values
            "current_policyname": policyname if policyname else None,
            "current_log_type": log_type if log_type else None,
            "current_threat_id": threat_id if threat_id else None,
            # Traffic analysis filter values
            "current_application": application if application else None,
            "current_session_end_reason": session_end_reason if session_end_reason else None,
            # Infrastructure filter values
            "current_src_zone": src_zone if src_zone else None,
            "current_dst_zone": dst_zone if dst_zone else None,
            # Aggregate view
            "is_aggregate": False,
            "current_view": '',
            "current_group_by": 'srcip,dstip,dstport',
            "group_fields": ['srcip', 'dstip', 'dstport'],
            "is_subnet_rollup": False,
            "agg_rows": [],
            "error": str(e),
        })


@router.get("/logs/detail-panel", response_class=HTMLResponse, name="log_detail_panel")
async def log_detail_panel(
    request: Request,
    timestamp: str = Query(..., description="Log timestamp in ISO format"),
    device: str = Query(..., description="Device IP"),
    index: int = Query(1, description="Row index for element IDs"),
    srcip: Optional[str] = Query(None),
    dstip: Optional[str] = Query(None),
    srcport: Optional[str] = Query(None),
    dstport: Optional[str] = Query(None),
    proto: Optional[str] = Query(None),
):
    """Return rendered HTML for a single log's detail panel (lazy-loaded on row expand)."""
    try:
        log = ClickHouseClient.get_log_by_id(
            timestamp=timestamp,
            device_ip=device,
            include_raw=True,
            srcip=srcip,
            dstip=dstip,
            srcport=srcport,
            dstport=dstport,
            proto=proto,
        )
        if not log:
            return HTMLResponse('<div class="detail-empty">Log entry not found</div>')

        pd = log.get('parsed_data', {})
        dev_ip = str(log.get('device_ip', ''))
        dev_vdom = log.get('vdom', '')
        dev_display = f"{dev_ip}_{dev_vdom}" if dev_vdom else dev_ip

        return _render("logs/_detail_panel.html", request, {
            "log": log,
            "pd": pd,
            "dev_display": dev_display,
            "index": index,
            "severity_map": SEVERITY_MAP,
        })
    except Exception as e:
        logger.error(f"Error in log_detail_panel: {e}")
        return HTMLResponse(f'<div class="detail-empty">Error loading details: {e}</div>')


@router.get("/policy-builder/", response_class=HTMLResponse, name="policy_builder")
async def policy_builder(
    request: Request,
    device: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None),
    page: Optional[str] = Query("1"),
    per_page: Optional[str] = Query("100"),
    srcip: Optional[str] = Query(None),
    dstip: Optional[str] = Query(None),
    dstport: Optional[str] = Query(None),
    policyname: Optional[str] = Query(None),
):
    """Policy Builder view - shows only denied traffic for policy analysis."""
    try:
        # Parse page and per_page with defaults
        try:
            page_num = int(page) if page and page.strip() else 1
            page_num = max(1, page_num)
        except (ValueError, TypeError):
            page_num = 1

        try:
            per_page_num = int(per_page) if per_page and per_page.strip() else 100
            per_page_num = max(10, min(200, per_page_num))
        except (ValueError, TypeError):
            per_page_num = 100

        offset = (page_num - 1) * per_page_num

        # Handle empty strings and convert severity to int
        device_ips = [device] if device and device.strip() else None
        severity_int = None
        if severity and severity.strip():
            try:
                severity_int = int(severity)
            except ValueError:
                severity_int = None
        severities = [severity_int] if severity_int is not None else None

        # Parse datetime strings
        start_time = None
        end_time = None
        now = datetime.now(timezone.utc)

        # Default to 1 hour for policy builder (faster initial load)
        default_time_range = '1h'
        effective_time_range = time_range.strip().lower() if time_range and time_range.strip() else default_time_range

        # Handle time_range parameter
        if effective_time_range.endswith('m'):
            try:
                minutes = int(effective_time_range[:-1])
                start_time = now - timedelta(minutes=minutes)
            except ValueError:
                pass
        elif effective_time_range.endswith('h'):
            try:
                hours = int(effective_time_range[:-1])
                start_time = now - timedelta(hours=hours)
            except ValueError:
                pass
        elif effective_time_range.endswith('d'):
            try:
                days = int(effective_time_range[:-1])
                start_time = now - timedelta(days=days)
            except ValueError:
                pass

        # Override with explicit start/end if provided
        if start:
            try:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))
            except ValueError:
                pass
        if end:
            try:
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))
            except ValueError:
                pass

        # Build search query - ALWAYS include deny filter for Policy Builder
        search_parts = []

        def _fmt(field, val):
            return f'{field}:"{val}"' if ' ' in val else f'{field}:{val}'

        # Handle srcip parameter
        srcip_clean = srcip.strip() if srcip and srcip.strip() else None
        if srcip_clean:
            search_parts.append(_fmt("srcip", srcip_clean))

        # Handle dstip parameter
        dstip_clean = dstip.strip() if dstip and dstip.strip() else None
        if dstip_clean:
            search_parts.append(_fmt("dstip", dstip_clean))

        # Handle dstport parameter
        dstport_clean = dstport.strip() if dstport and dstport.strip() else None
        if dstport_clean:
            search_parts.append(_fmt("dstport", dstport_clean))

        # Handle policyname parameter
        policyname_clean = policyname.strip() if policyname and policyname.strip() else None
        if policyname_clean:
            search_parts.append(_fmt("policyname", policyname_clean))

        # Combine with existing q parameter if present
        search_query = q or ""
        if search_parts:
            direct_filters = " ".join(search_parts)
            if search_query:
                search_query = f"{search_query} {direct_filters}"
            else:
                search_query = direct_filters

        # ALWAYS add deny filter for Policy Builder page
        deny_filter = 'action:deny|drop|block|reject'
        if search_query:
            search_query = f"{search_query} {deny_filter}"
        else:
            search_query = deny_filter

        # Run all ClickHouse queries in parallel
        loop = asyncio.get_event_loop()

        logs_future = loop.run_in_executor(
            _executor,
            lambda: ClickHouseClient.search_logs(
                limit=per_page_num,
                offset=offset,
                device_ips=device_ips,
                severities=severities,
                start_time=start_time,
                end_time=end_time,
                query_text=search_query,
            )
        )

        total_future = loop.run_in_executor(
            _executor,
            lambda: ClickHouseClient.count_logs(
                device_ips=device_ips,
                severities=severities,
                start_time=start_time,
                end_time=end_time,
                query_text=search_query,
            )
        )

        stats_future = loop.run_in_executor(
            _executor,
            lambda: ClickHouseClient.get_log_stats_summary(
                device_ips=device_ips,
                start_time=start_time,
                end_time=end_time,
                query_text=search_query,
            )
        )

        devices_future = loop.run_in_executor(
            _executor,
            ClickHouseClient.get_distinct_devices
        )

        # Wait for all queries to complete
        logs, total, stats, devices = await asyncio.gather(
            logs_future, total_future, stats_future, devices_future
        )

        # Convert non-JSON-serializable objects to strings for template
        for log in logs:
            if 'device_ip' in log:
                log['device_ip'] = str(log['device_ip'])
            if 'timestamp' in log:
                log['timestamp'] = log['timestamp'].isoformat() if hasattr(log['timestamp'], 'isoformat') else str(log['timestamp'])

        total_pages = (total + per_page_num - 1) // per_page_num if total > 0 else 1

        # Clean up filter values for template
        current_device = device if device and device.strip() else None
        current_q = q if q and q.strip() else None

        return _render("logs/policy_builder.html", request, {
            "logs": logs,
            "severity_map": SEVERITY_MAP,
            "devices": devices,
            "total": total,
            "stats": stats,
            "page": page_num,
            "per_page": per_page_num,
            "total_pages": total_pages,
            "has_prev": page_num > 1,
            "has_next": page_num < total_pages,
            # Current filters
            "current_device": current_device,
            "current_severity": severity_int,
            "current_q": current_q,
            "current_start": start,
            "current_end": end,
            "current_time_range": effective_time_range,
            # New direct filter values
            "current_srcip": srcip_clean,
            "current_dstip": dstip_clean,
            "current_dstport": dstport_clean,
            "current_policyname": policyname_clean,
            "error": None,
        })
    except Exception as e:
        import traceback
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in policy_builder view: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        return _render("logs/policy_builder.html", request, {
            "logs": [],
            "severity_map": SEVERITY_MAP,
            "devices": [],
            "total": 0,
            "stats": {},
            "page": 1,
            "per_page": 100,
            "total_pages": 1,
            "has_prev": False,
            "has_next": False,
            "current_device": None,
            "current_severity": None,
            "current_q": None,
            "current_start": start if start else None,
            "current_end": end if end else None,
            "current_srcip": srcip if srcip else None,
            "current_dstip": dstip if dstip else None,
            "current_dstport": dstport if dstport else None,
            "current_policyname": policyname if policyname else None,
            "error": str(e),
        })


def _suggest_rule_cli(parser: str, dstip: str, dstport: int,
                       srcip: Optional[str], src_zone: Optional[str] = None,
                       dst_zone: Optional[str] = None) -> str:
    """Generate a minimal vendor-correct allow-rule CLI snippet.

    Used by the Policy Lookup "Devices with Gap" panel so an operator can
    copy-paste a starter rule that closes the gap.
    """
    src = (srcip or 'all').strip()
    rule_name = f"Allow_{(srcip or 'any').replace('.', '_')}_to_{dstip.replace('.', '_')}_{dstport}"[:63]
    p = (parser or '').upper()

    if p == 'FORTINET':
        srcaddr = f'"{srcip}"' if srcip else '"all"'
        return (
            "config firewall policy\n"
            "    edit 0\n"
            f'        set name "{rule_name}"\n'
            f'        set srcintf "{src_zone or "any"}"\n'
            f'        set dstintf "{dst_zone or "any"}"\n'
            f'        set srcaddr {srcaddr}\n'
            f'        set dstaddr "{dstip}"\n'
            f'        set service "PORT_{dstport}_TCP"\n'
            "        set action accept\n"
            '        set schedule "always"\n'
            "        set logtraffic all\n"
            "    next\n"
            "end\n"
            f"# NOTE: define address objects for {dstip}"
            f"{' and ' + srcip if srcip else ''} and a service object for tcp/{dstport} first."
        )
    if p == 'PALOALTO':
        srcline = src
        return (
            "configure\n"
            f"set rulebase security rules {rule_name} \\\n"
            f"  from {src_zone or 'any'} to {dst_zone or 'any'} \\\n"
            f"  source {srcline} destination {dstip} \\\n"
            f"  application any service service-tcp-{dstport} \\\n"
            "  action allow log-end yes\n"
            "commit\n"
            f"# NOTE: create service-tcp-{dstport} (or reuse service-https for 443) "
            "and address objects as needed."
        )
    # Generic / unknown vendor — just describe the intent.
    return (
        f"# Suggested rule (vendor unknown, please adapt to your CLI)\n"
        f"# Action : allow\n"
        f"# Source : {src}{(' (zone ' + src_zone + ')') if src_zone else ''}\n"
        f"# Destination: {dstip}{(' (zone ' + dst_zone + ')') if dst_zone else ''}\n"
        f"# Service: tcp/{dstport}\n"
    )


@router.get("/policy-lookup/", response_class=HTMLResponse, name="policy_lookup")
async def policy_lookup_page(
    request: Request,
    dstip: Optional[str] = Query(None),
    dstport: Optional[str] = Query(None),
    srcip: Optional[str] = Query(None),
    time_range: Optional[str] = Query("24h"),
    db: AsyncSession = Depends(get_db),
):
    """Policy lookup — find existing allow/deny policies for a destination."""
    results = None
    error = None

    dstip_clean = dstip.strip() if dstip and dstip.strip() else None
    dstport_clean = dstport.strip() if dstport and dstport.strip() else None
    srcip_clean = srcip.strip() if srcip and srcip.strip() else None

    if dstip_clean and dstport_clean:
        try:
            port_int = int(dstport_clean)

            # Parse time range
            start_time = None
            end_time = None
            now = datetime.now(timezone.utc)
            effective = (time_range or "24h").strip().lower()

            if effective.endswith('h'):
                try:
                    start_time = now - timedelta(hours=int(effective[:-1]))
                except ValueError:
                    pass
            elif effective.endswith('d'):
                try:
                    start_time = now - timedelta(days=int(effective[:-1]))
                except ValueError:
                    pass

            default_hours = 24
            if start_time:
                default_hours = max(1, int((now - start_time).total_seconds() / 3600))

            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                _executor,
                lambda: ClickHouseClient.policy_lookup(
                    dstip=dstip_clean,
                    dstport=port_int,
                    srcip=srcip_clean,
                    start_time=start_time,
                    end_time=end_time,
                    default_hours=default_hours,
                )
            )

            # ── Phase 2: vendor-aware suggested rule per gap device ──
            # Look up parser type for each gap device's IP (strip the optional
            # _vdom suffix), then render a starter CLI snippet.
            gap_devices = results.get('gap_devices') or []
            if gap_devices:
                gap_ips = sorted({d.split('_', 1)[0] for d in gap_devices})
                # ip_address column is INET; cast to text for the VARCHAR IN().
                ip_text = cast(Device.ip_address, String)
                rows = (await db.execute(
                    select(ip_text.label('ip'), Device.parser).where(ip_text.in_(gap_ips))
                )).all()
                parser_by_ip = {ip: parser for ip, parser in rows}
                # Pull a representative src_zone/dst_zone from any denied row
                # for this device, when available (improves CLI quality).
                zone_by_dev: dict = {}
                for r in results.get('denied') or []:
                    key = r['device_display']
                    if key in gap_devices and key not in zone_by_dev:
                        zone_by_dev[key] = (r.get('src_zone') or '', r.get('dst_zone') or '')
                results['gap_suggestions'] = {
                    dev: _suggest_rule_cli(
                        parser_by_ip.get(dev.split('_', 1)[0], 'GENERIC'),
                        dstip_clean, port_int, srcip_clean,
                        zone_by_dev.get(dev, ('', ''))[0] or None,
                        zone_by_dev.get(dev, ('', ''))[1] or None,
                    )
                    for dev in gap_devices
                }
                results['gap_parsers'] = {
                    dev: parser_by_ip.get(dev.split('_', 1)[0], 'GENERIC')
                    for dev in gap_devices
                }
        except ValueError as ve:
            error = str(ve)
        except Exception as e:
            logger.error(f"Policy lookup error: {e}")
            error = str(e)

    return _render("logs/policy_lookup.html", request, {
        "results": results,
        "current_dstip": dstip_clean,
        "current_dstport": dstport_clean,
        "current_srcip": srcip_clean,
        "current_time_range": (time_range or "24h").strip().lower(),
        "error": error,
        "format_number": format_number,
    })


@router.get("/devices/", response_class=HTMLResponse, name="device_list")
async def device_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Device list view."""
    try:
        result = await db.execute(select(Device).order_by(Device.created_at.desc()))
        devices = result.scalars().all()

        # Get storage stats
        try:
            storage_stats = ClickHouseClient.get_storage_stats()
            per_device_storage = ClickHouseClient.get_per_device_storage()
            device_storage_map = {s['device_ip']: s for s in per_device_storage}
        except Exception:
            storage_stats = {
                'total_rows': 0,
                'compressed_size': '0 B',
                'uncompressed_size': '0 B',
                'compression_ratio': 0,
            }
            device_storage_map = {}

        return _render("devices/device_list.html", request, {
            "devices": devices,
            "storage_stats": storage_stats,
            "device_storage_map": device_storage_map,
            "format_bytes": format_bytes,
            "format_number": format_number,
        })
    except Exception as e:
        return _render("devices/device_list.html", request, {
            "devices": [],
            "storage_stats": {},
            "device_storage_map": {},
            "format_bytes": format_bytes,
            "format_number": format_number,
            "error": str(e),
        })


@router.get("/devices/{device_id}/edit/", response_class=HTMLResponse, name="edit_device",
            dependencies=[Depends(require_role("ADMIN"))])
async def edit_device(
    request: Request,
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Device edit form."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return RedirectResponse(url="/devices/")

    ssh_host_result = await db.execute(
        select(DeviceSshSettings)
        .where(DeviceSshSettings.device_id == device_id)
        .limit(1)
    )
    ssh_settings = ssh_host_result.scalar_one_or_none()
    ssh_host = ssh_settings.ssh_host if ssh_settings else ""

    # Optional Fortinet VDOM configuration (used for routing table collection)
    current_vdom = None
    if device.parser == ParserType.FORTINET:
        vdom_result = await db.execute(
            select(DeviceVdom)
            .where(
                DeviceVdom.device_id == device_id,
                DeviceVdom.is_active == True,
            )
            .order_by(DeviceVdom.is_default.desc(), DeviceVdom.vdom_name)
            .limit(1)
        )
        vdom_obj = vdom_result.scalar_one_or_none()
        current_vdom = vdom_obj.vdom_name if vdom_obj else None

    return _render("devices/edit_device.html", request, {
        "device": device,
        "parser_choices": ParserType.CHOICES,
        "retention_choices": RetentionDays.CHOICES,
        "current_vdom": current_vdom,
        "ssh_host": ssh_host,
    })


@router.post("/devices/{device_id}/edit/", name="edit_device_post",
             dependencies=[Depends(require_role("ADMIN"))])
async def edit_device_post(
    device_id: int,
    hostname: str = Form(""),
    parser: str = Form("GENERIC"),
    retention_days: int = Form(90),
    ssh_host: str = Form(""),
    use_vdom: Optional[str] = Form(None),
    vdom_name: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    """Handle device edit form submission."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if device:
        device.hostname = hostname or None
        device.parser = parser
        device.retention_days = retention_days

        # SSH target override (optional)
        ssh_host_clean = (ssh_host or "").strip()
        ssh_host_result = await db.execute(
            select(DeviceSshSettings)
            .where(DeviceSshSettings.device_id == device_id)
            .limit(1)
        )
        ssh_settings = ssh_host_result.scalar_one_or_none()

        if ssh_host_clean:
            if ssh_settings:
                ssh_settings.ssh_host = ssh_host_clean
            else:
                db.add(DeviceSshSettings(device_id=device_id, ssh_host=ssh_host_clean))
        else:
            if ssh_settings:
                await db.delete(ssh_settings)

        # Fortinet VDOM routing fetch configuration:
        # - If enabled and a VDOM name is provided, keep only that VDOM active/default.
        # - Otherwise, disable all VDOMs so routing is fetched from global context.
        vdom_enabled = use_vdom == "on"
        vdom_clean = (vdom_name or "").strip()

        vdoms_result = await db.execute(
            select(DeviceVdom).where(DeviceVdom.device_id == device_id)
        )
        existing_vdoms = vdoms_result.scalars().all()

        if device.parser == ParserType.FORTINET and vdom_enabled and vdom_clean:
            # Disable all first (simplifies "VDOM vs non-VDOM" behavior from the edit page).
            for v in existing_vdoms:
                v.is_active = False
                v.is_default = False

            target = next((v for v in existing_vdoms if v.vdom_name == vdom_clean), None)
            if not target:
                target = DeviceVdom(
                    device_id=device_id,
                    vdom_name=vdom_clean,
                    is_active=True,
                    is_default=True,
                )
                db.add(target)
            else:
                target.is_active = True
                target.is_default = True
        else:
            # Not Fortinet or VDOM not enabled: ensure global-context fetch by disabling VDOMs.
            for v in existing_vdoms:
                v.is_active = False
                v.is_default = False

        await db.commit()

    return RedirectResponse(url="/devices/", status_code=303)


@router.get("/devices/{device_id}/approve/", name="approve_device_view",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def approve_device_view(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Approve a device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if device:
        device.status = DeviceStatus.APPROVED
        await db.commit()

    return RedirectResponse(url="/devices/", status_code=303)


@router.get("/devices/{device_id}/reject/", name="reject_device_view",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def reject_device_view(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Reject a device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if device:
        device.status = DeviceStatus.REJECTED
        await db.commit()

    return RedirectResponse(url="/devices/", status_code=303)


# ============================================================
# Device Detail & Routing Table Endpoints
# ============================================================

@router.get("/devices/{device_id}/", response_class=HTMLResponse, name="device_detail")
async def device_detail(
    request: Request,
    device_id: int,
    vdom: Optional[str] = None,
    tab: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Device detail page with routing table and zone data."""
    from sqlalchemy import func, desc
    from ..services.routing_service import RoutingService
    from ..services.zone_service import ZoneService

    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return RedirectResponse(url="/devices/")

    # Get credentials count
    creds_result = await db.execute(
        select(func.count(DeviceCredential.id))
        .where(DeviceCredential.device_id == device_id)
    )
    credentials_count = creds_result.scalar() or 0

    # Any active credential (SSH or API) is enough to drive routing/zone/policy
    # fetches — the services pick the best transport per device.
    active_cred_result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type.in_(['SSH', 'API']),
        )
        .limit(1)
    )
    has_credentials = active_cred_result.scalar_one_or_none() is not None

    # Get configured VDOMs for this device
    configured_vdoms = await RoutingService.get_device_vdoms(device_id, db)

    # Get available VDOMs that have routing data
    available_vdoms = await RoutingService.get_available_vdoms(device_id, db)

    # Determine which VDOM to show (from query param, or first available, or None)
    selected_vdom = vdom
    if not selected_vdom and available_vdoms:
        # Default to first available VDOM that has data
        selected_vdom = available_vdoms[0] if available_vdoms else None

    # Get latest routing table for selected VDOM
    if selected_vdom:
        snapshot, routes = await RoutingService.get_latest_routes_by_vdom(device_id, db, vdom=selected_vdom)
    else:
        snapshot, routes = await RoutingService.get_latest_routes(device_id, db)

    # Get route statistics
    route_stats = {
        'total': len(routes),
        'by_type': {},
        'default_routes': 0,
    }
    for r in routes:
        rt = r.route_type
        route_stats['by_type'][rt] = route_stats['by_type'].get(rt, 0) + 1
        if r.is_default:
            route_stats['default_routes'] += 1

    # Get route changes
    changes = await RoutingService.get_route_changes(device_id, db, limit=50)

    # Get snapshots history
    snapshots = await RoutingService.get_snapshots(device_id, db, limit=20)

    # Get zone/interface data
    zone_snapshot = await ZoneService.get_latest_snapshot(device_id, db, vdom=selected_vdom)
    zone_table_data = await ZoneService.get_zone_interface_table(device_id, db, vdom=selected_vdom)

    # Get firewall policy data (Phase 1: Fortinet only).
    from ..services.firewall_policy_service import FirewallPolicyService
    fw_snapshot = await FirewallPolicyService.get_latest_snapshot(device_id, db, vdom=selected_vdom)
    fw_policies = await FirewallPolicyService.get_policies(device_id, db, vdom=selected_vdom, limit=500)
    fw_addresses = await FirewallPolicyService.get_address_objects(device_id, db, vdom=selected_vdom)
    fw_services = await FirewallPolicyService.get_service_objects(device_id, db, vdom=selected_vdom)
    # Quick name → object lookups so the policy detail panel can resolve
    # `srcaddr=["AppServers"]` into the real CIDR/IPs without per-row queries.
    # Serialise to plain dicts here (Jinja can't do dict comprehensions).
    fw_addr_map_json = {
        a.name: {
            "kind": a.kind, "value": a.value,
            "members": a.members, "comment": a.comment,
        } for a in fw_addresses
    }
    fw_svc_map_json = {
        s.name: {
            "protocol": s.protocol, "ports": s.ports,
            "members": s.members, "category": s.category,
        } for s in fw_services
    }
    # Policy analytics: Phase 1 (config-only) + Phase 2 (log join).
    # Coerce INET → str so the ClickHouse query gets a clean IP.
    from ..services.policy_analytics_service import PolicyAnalyticsService
    fw_analytics = PolicyAnalyticsService.compute(
        fw_policies, fw_addresses, fw_services,
        device_ip=str(device.ip_address) if device else None,
        log_window_hours=720,  # 30 days
    )

    # Validate and default current tab
    valid_tabs = ['routes', 'zones', 'policies', 'analytics', 'changes', 'snapshots']
    current_tab = tab if tab in valid_tabs else 'routes'

    return _render("devices/device_detail.html", request, {
        "device": device,
        "credentials_count": credentials_count,
        "has_credentials": has_credentials,
        "snapshot": snapshot,
        "routes": routes,
        "route_stats": route_stats,
        "changes": changes,
        "snapshots": snapshots,
        "configured_vdoms": configured_vdoms,
        "available_vdoms": available_vdoms,
        "selected_vdom": selected_vdom,
        "zone_snapshot": zone_snapshot,
        "zone_table_data": zone_table_data,
        "fw_snapshot": fw_snapshot,
        "fw_policies": fw_policies,
        "fw_addresses": fw_addresses,
        "fw_services": fw_services,
        "fw_addr_map_json": fw_addr_map_json,
        "fw_svc_map_json": fw_svc_map_json,
        "fw_analytics": fw_analytics,
        "current_tab": current_tab,
    })


async def _pick_fetch_credential(device_id: int, db: AsyncSession):
    """Return the best available credential for an automated fetch, preferring
    API tokens over SSH (faster, more reliable, no shell-privilege issues)."""
    api_q = await db.execute(
        select(DeviceCredential).where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type == 'API',
        ).limit(1)
    )
    api_cred = api_q.scalar_one_or_none()
    if api_cred:
        return api_cred
    ssh_q = await db.execute(
        select(DeviceCredential).where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type == 'SSH',
        ).limit(1)
    )
    return ssh_q.scalar_one_or_none()


@router.post("/devices/{device_id}/fetch-routes/", name="fetch_routing_table")
async def fetch_routing_table(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Fetch routing table from device via SSH."""
    from ..services.routing_service import RoutingService

    # Get device
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return JSONResponse({"success": False, "message": "Device not found"}, status_code=404)

    credential = await _pick_fetch_credential(device_id, db)
    if not credential:
        return JSONResponse({"success": False, "message": "No SSH or API credentials configured"})

    # Fetch routing tables for all VDOMs (or global if no VDOMs configured)
    results = await RoutingService.fetch_all_vdom_routing_tables(device, credential, db)

    # Aggregate results
    total_routes = 0
    vdom_results = []
    overall_success = False

    for vdom_name, (success, message, snapshot) in results.items():
        route_count = snapshot.route_count if snapshot else 0
        total_routes += route_count
        vdom_results.append({
            "vdom": vdom_name,
            "success": success,
            "message": message,
            "route_count": route_count
        })
        if success:
            overall_success = True

    succeeded = [r for r in vdom_results if r["success"]]
    failed = [r for r in vdom_results if not r["success"]]

    if len(vdom_results) > 1:
        summary_message = (
            f"Routing fetch completed: {len(succeeded)}/{len(vdom_results)} VDOM(s) succeeded"
        )
        if failed:
            summary_message += "; failed: " + ", ".join(str(r["vdom"]) for r in failed)
    else:
        summary_message = vdom_results[0]["message"] if vdom_results else "No VDOMs configured"

    return JSONResponse({
        "success": overall_success,
        "message": summary_message,
        "route_count": total_routes,
        "vdom_results": vdom_results
    })


@router.post("/devices/{device_id}/fetch-zones/", name="fetch_zone_data")
async def fetch_zone_data(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Fetch zone/interface data from device via SSH."""
    from ..services.zone_service import ZoneService

    # Get device
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return JSONResponse({"success": False, "message": "Device not found"}, status_code=404)

    credential = await _pick_fetch_credential(device_id, db)
    if not credential:
        return JSONResponse({"success": False, "message": "No SSH or API credentials configured"})

    # Fetch zone data for all VDOMs (or global if no VDOMs configured)
    results = await ZoneService.fetch_all_vdom_zone_data(device, credential, db)

    # Aggregate results
    total_zones = 0
    total_interfaces = 0
    vdom_results = []
    overall_success = False

    for vdom_name, (success, message, snapshot) in results.items():
        zone_count = snapshot.zone_count if snapshot else 0
        intf_count = snapshot.interface_count if snapshot else 0
        total_zones += zone_count
        total_interfaces += intf_count
        vdom_results.append({
            "vdom": vdom_name,
            "success": success,
            "message": message,
            "zone_count": zone_count,
            "interface_count": intf_count
        })
        if success:
            overall_success = True

    succeeded = [r for r in vdom_results if r["success"]]
    failed = [r for r in vdom_results if not r["success"]]

    if len(vdom_results) > 1:
        summary_message = (
            f"Zone fetch completed: {len(succeeded)}/{len(vdom_results)} VDOM(s) succeeded"
        )
        if failed:
            summary_message += "; failed: " + ", ".join(str(r["vdom"]) for r in failed)
    else:
        summary_message = vdom_results[0]["message"] if vdom_results else "No VDOMs configured"

    return JSONResponse({
        "success": overall_success,
        "message": summary_message,
        "zone_count": total_zones,
        "interface_count": total_interfaces,
        "vdom_results": vdom_results
    })


@router.post("/devices/{device_id}/fetch-policies/", name="fetch_firewall_policies")
async def fetch_firewall_policies(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Fetch firewall policy / rule base + objects from device via SSH."""
    from ..services.firewall_policy_service import FirewallPolicyService

    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        return JSONResponse({"success": False, "message": "Device not found"}, status_code=404)

    credential = await _pick_fetch_credential(device_id, db)
    if not credential:
        return JSONResponse({"success": False, "message": "No SSH or API credentials configured"})

    results = await FirewallPolicyService.fetch_all_vdom_policies(device, credential, db)

    total_policies = 0
    total_addrs = 0
    total_services = 0
    vdom_results = []
    overall_success = False

    for vdom_name, (success, message, snapshot) in results.items():
        policy_count = snapshot.policy_count if snapshot else 0
        addr_count = (snapshot.address_count + snapshot.addrgrp_count) if snapshot else 0
        svc_count = (snapshot.service_count + snapshot.servicegrp_count) if snapshot else 0
        total_policies += policy_count
        total_addrs += addr_count
        total_services += svc_count
        vdom_results.append({
            "vdom": vdom_name,
            "success": success,
            "message": message,
            "policy_count": policy_count,
            "address_count": addr_count,
            "service_count": svc_count,
        })
        if success:
            overall_success = True

    failed = [r for r in vdom_results if not r["success"]]
    if len(vdom_results) > 1:
        summary = f"Policy fetch: {len(vdom_results) - len(failed)}/{len(vdom_results)} VDOM(s) succeeded"
        if failed:
            summary += "; failed: " + ", ".join(str(r["vdom"]) for r in failed)
    else:
        summary = vdom_results[0]["message"] if vdom_results else "No VDOMs configured"

    return JSONResponse({
        "success": overall_success,
        "message": summary,
        "policy_count": total_policies,
        "address_count": total_addrs,
        "service_count": total_services,
        "vdom_results": vdom_results,
    })


# ============================================================
# Device Credentials Endpoints
# ============================================================

@router.get("/devices/{device_id}/credentials/", response_class=HTMLResponse, name="device_credentials",
            dependencies=[Depends(require_role("ADMIN"))])
async def device_credentials(
    request: Request,
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Device credentials management page."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return RedirectResponse(url="/devices/")

    # Get credentials
    creds_result = await db.execute(
        select(DeviceCredential)
        .where(DeviceCredential.device_id == device_id)
        .order_by(DeviceCredential.created_at.desc())
    )
    credentials = creds_result.scalars().all()

    # Get VDOMs (for Fortinet devices)
    vdoms_result = await db.execute(
        select(DeviceVdom)
        .where(DeviceVdom.device_id == device_id)
        .order_by(DeviceVdom.is_default.desc(), DeviceVdom.vdom_name)
    )
    vdoms = vdoms_result.scalars().all()

    return _render("devices/device_credentials.html", request, {
        "device": device,
        "credentials": credentials,
        "credential_types": CredentialType.CHOICES,
        "vdoms": vdoms,
    })


@router.post("/devices/{device_id}/credentials/add/", name="add_credential",
             dependencies=[Depends(require_role("ADMIN"))])
async def add_credential(
    device_id: int,
    credential_type: str = Form("SSH"),
    username: str = Form(...),
    password: str = Form(...),
    port: int = Form(22),
    description: str = Form(""),
    is_active: bool = Form(True),
    db: AsyncSession = Depends(get_db),
):
    """Add new credential for device."""
    # Verify device exists
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return RedirectResponse(url="/devices/", status_code=303)

    # Create credential
    credential = DeviceCredential(
        device_id=device_id,
        credential_type=credential_type,
        username=username,
        port=port,
        description=description if description else None,
        is_active=is_active if isinstance(is_active, bool) else is_active == "on",
    )
    credential.password = password  # This encrypts the password

    db.add(credential)
    await db.commit()

    return RedirectResponse(
        url=f"/devices/{device_id}/credentials/",
        status_code=303
    )


@router.post("/devices/{device_id}/credentials/update/", name="update_credential",
             dependencies=[Depends(require_role("ADMIN"))])
async def update_credential(
    device_id: int,
    credential_id: int = Form(...),
    credential_type: str = Form("SSH"),
    username: str = Form(...),
    password: str = Form(""),
    port: int = Form(22),
    description: str = Form(""),
    is_active: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Update existing credential."""
    result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.id == credential_id,
            DeviceCredential.device_id == device_id
        )
    )
    credential = result.scalar_one_or_none()

    if not credential:
        return RedirectResponse(url=f"/devices/{device_id}/credentials/", status_code=303)

    credential.credential_type = credential_type
    credential.username = username
    credential.port = port
    credential.description = description if description else None
    credential.is_active = is_active if isinstance(is_active, bool) else is_active == "on"

    # Only update password if provided
    if password:
        credential.password = password

    await db.commit()

    return RedirectResponse(
        url=f"/devices/{device_id}/credentials/",
        status_code=303
    )


@router.post("/devices/{device_id}/credentials/{credential_id}/delete/", name="delete_credential",
             dependencies=[Depends(require_role("ADMIN"))])
async def delete_credential(
    device_id: int,
    credential_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a credential."""
    result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.id == credential_id,
            DeviceCredential.device_id == device_id
        )
    )
    credential = result.scalar_one_or_none()

    if credential:
        await db.delete(credential)
        await db.commit()
        return JSONResponse({"success": True})

    return JSONResponse({"success": False, "message": "Credential not found"}, status_code=404)


@router.post("/devices/{device_id}/credentials/{credential_id}/test/", name="test_credential",
             dependencies=[Depends(require_role("ADMIN"))])
async def test_credential(
    device_id: int,
    credential_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Test SSH credential connection."""
    from ..services.ssh_service import SSHService

    # Get device and credential
    device_result = await db.execute(select(Device).where(Device.id == device_id))
    device = device_result.scalar_one_or_none()

    if not device:
        return JSONResponse({"success": False, "message": "Device not found"}, status_code=404)

    cred_result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.id == credential_id,
            DeviceCredential.device_id == device_id
        )
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        return JSONResponse({"success": False, "message": "Credential not found"}, status_code=404)

    # Update last_used
    credential.last_used = datetime.utcnow()

    # device.ip_address comes back from the INET column as an ipaddress.IPv4Address
    # object; paramiko/socket need a plain string.
    ssh_host = str(device.ip_address)
    ssh_host_result = await db.execute(
        select(DeviceSshSettings.ssh_host)
        .where(DeviceSshSettings.device_id == device_id)
        .limit(1)
    )
    ssh_host_override = ssh_host_result.scalar_one_or_none()
    if ssh_host_override:
        override = str(ssh_host_override).strip()
        if override:
            ssh_host = override

    # Vendor / transport branch: API test = quick auth-probe against the
    # device's REST API; SSH test = TCP+auth handshake (defined elsewhere).
    loop = asyncio.get_event_loop()
    if (credential.credential_type or "SSH").upper() == "API":
        def _probe_fortinet_api():
            import time as _t
            from ..services.fortinet_api_service import FortinetAPIClient, FortinetAPIError
            client = FortinetAPIClient(
                host=ssh_host, token=credential.password,
                port=credential.port or 443,
            )
            t0 = _t.time()
            try:
                status = client.system_status()
                ms = int((_t.time() - t0) * 1000)
                # Surface hostname/version when available so the operator
                # can confirm they hit the right device.
                hostname = (status.get("results") or {}).get("hostname") or status.get("hostname")
                version = (status.get("results") or {}).get("version") or status.get("version")
                msg = f"FortiGate API OK"
                if hostname or version:
                    msg += f" ({hostname or ''} {version or ''})".rstrip()
                return type("R", (), {"success": True, "error": msg, "duration_ms": ms})()
            except FortinetAPIError as e:
                ms = int((_t.time() - t0) * 1000)
                return type("R", (), {"success": False, "error": str(e), "duration_ms": ms})()
            except Exception as e:
                ms = int((_t.time() - t0) * 1000)
                return type("R", (), {"success": False, "error": f"{type(e).__name__}: {e}", "duration_ms": ms})()
        result = await loop.run_in_executor(_executor, _probe_fortinet_api)
    else:
        result = await loop.run_in_executor(
            _executor,
            lambda: SSHService.test_connection(
                host=ssh_host,
                username=credential.username,
                password=credential.password,
                port=credential.port
            )
        )

    if result.success:
        credential.last_success = datetime.utcnow()

    await db.commit()

    # When the test passes, the API path packs hostname/version into
    # `result.error` for display; SSH path leaves it None.
    if result.success:
        message = result.error or "Connection successful"
    else:
        message = result.error or "Test failed"
    return JSONResponse({
        "success": result.success,
        "message": message,
        "duration_ms": result.duration_ms
    })


# ============================================================
# VDOM Management Endpoints
# ============================================================

@router.post("/devices/{device_id}/vdoms/add/", name="add_vdom")
async def add_vdom(
    device_id: int,
    vdom_name: str = Form(...),
    description: str = Form(""),
    is_active: bool = Form(True),
    is_default: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Add new VDOM for device."""
    # Verify device exists
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        return RedirectResponse(url="/devices/", status_code=303)

    # If setting as default, unset other defaults
    if is_default if isinstance(is_default, bool) else is_default == "on":
        existing_defaults = await db.execute(
            select(DeviceVdom)
            .where(DeviceVdom.device_id == device_id, DeviceVdom.is_default == True)
        )
        for vdom in existing_defaults.scalars().all():
            vdom.is_default = False

    # Create VDOM
    vdom = DeviceVdom(
        device_id=device_id,
        vdom_name=vdom_name.strip(),
        description=description.strip() if description else None,
        is_active=is_active if isinstance(is_active, bool) else is_active == "on",
        is_default=is_default if isinstance(is_default, bool) else is_default == "on",
    )

    db.add(vdom)
    await db.commit()

    return RedirectResponse(
        url=f"/devices/{device_id}/credentials/",
        status_code=303
    )


@router.post("/devices/{device_id}/vdoms/update/", name="update_vdom")
async def update_vdom(
    device_id: int,
    vdom_id: int = Form(...),
    vdom_name: str = Form(...),
    description: str = Form(""),
    is_active: bool = Form(False),
    is_default: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Update existing VDOM."""
    result = await db.execute(
        select(DeviceVdom)
        .where(
            DeviceVdom.id == vdom_id,
            DeviceVdom.device_id == device_id
        )
    )
    vdom = result.scalar_one_or_none()

    if not vdom:
        return RedirectResponse(url=f"/devices/{device_id}/credentials/", status_code=303)

    # If setting as default, unset other defaults
    new_is_default = is_default if isinstance(is_default, bool) else is_default == "on"
    if new_is_default and not vdom.is_default:
        existing_defaults = await db.execute(
            select(DeviceVdom)
            .where(
                DeviceVdom.device_id == device_id,
                DeviceVdom.is_default == True,
                DeviceVdom.id != vdom_id
            )
        )
        for other_vdom in existing_defaults.scalars().all():
            other_vdom.is_default = False

    vdom.vdom_name = vdom_name.strip()
    vdom.description = description.strip() if description else None
    vdom.is_active = is_active if isinstance(is_active, bool) else is_active == "on"
    vdom.is_default = new_is_default

    await db.commit()

    return RedirectResponse(
        url=f"/devices/{device_id}/credentials/",
        status_code=303
    )


@router.post("/devices/{device_id}/vdoms/{vdom_id}/delete/", name="delete_vdom")
async def delete_vdom(
    device_id: int,
    vdom_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a VDOM."""
    result = await db.execute(
        select(DeviceVdom)
        .where(
            DeviceVdom.id == vdom_id,
            DeviceVdom.device_id == device_id
        )
    )
    vdom = result.scalar_one_or_none()

    if vdom:
        await db.delete(vdom)
        await db.commit()
        return JSONResponse({"success": True})

    return JSONResponse({"success": False, "message": "VDOM not found"}, status_code=404)


# ============================================================
# Policy Builder API Endpoint
# ============================================================

@router.post("/api/build-policy/", name="build_policy")
async def build_policy(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Build firewall CLI commands from log data.
    Supports both Fortinet (FortiGate) and Palo Alto Networks firewalls.

    Accepts JSON body with:
    - log_data: Dict containing srcip, dstip, dstport, protocol, zones, interfaces
    - device_ip: Optional device IP to fetch zone table for IP-to-zone matching
    - vdom: Optional VDOM name
    - policy_name: Optional custom policy name
    - vendor: Firewall vendor - 'fortinet' (default) or 'paloalto'
    """
    from ..services.policy_builder_service import PolicyBuilderService
    from ..services.zone_service import ZoneService

    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(
            {"success": False, "error": f"Invalid JSON: {str(e)}"},
            status_code=400
        )

    log_data = body.get('log_data', {})
    device_ip = body.get('device_ip')
    vdom = body.get('vdom')
    policy_name = body.get('policy_name')
    vendor = body.get('vendor', 'fortinet')  # Default to Fortinet

    if not log_data:
        return JSONResponse(
            {"success": False, "error": "log_data is required"},
            status_code=400
        )

    try:
        # Get zone table if device_ip is provided
        # NOTE: Don't filter by vdom for IP-to-zone matching - we want to find
        # which zone the IP belongs to regardless of where the log came from
        zone_table = None
        if device_ip:
            # Find device by IP - use host() function for inet column comparison
            # (casting inet to text adds /32 suffix which breaks comparison)
            from sqlalchemy import func
            device_result = await db.execute(
                select(Device).where(func.host(Device.ip_address) == device_ip)
            )
            device = device_result.scalar_one_or_none()

            if device:
                # Get zone/interface table for this device - NO vdom filter
                # This ensures we can match IPs to zones in any VDOM
                zone_table = await ZoneService.get_zone_interface_table(
                    device.id, db, vdom=None  # Always get all zones for IP matching
                )

        # Fetch address objects for name lookup
        from ..models.address_object import AddressObject
        ao_result = await db.execute(select(AddressObject).order_by(AddressObject.name.asc()))
        ao_list = [
            {"name": o.name, "obj_type": o.obj_type, "value": o.value}
            for o in ao_result.scalars().all()
        ]

        # Build the policy CLI
        result = PolicyBuilderService.build_policy_from_log(
            log_data=log_data,
            zone_table=zone_table,
            vdom=vdom,
            custom_name=policy_name,
            vendor=vendor,
            address_objects=ao_list
        )

        return JSONResponse({
            "success": True,
            "cli": result['cli'],
            "components": result['components'],
            "metadata": result['metadata']
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            {"success": False, "error": str(e)},
            status_code=500
        )


# ============================================================
# System Monitoring Endpoints
# ============================================================

def get_disk_usage(path: str = '/') -> dict:
    """Get disk usage statistics for the specified path."""
    import shutil
    total, used, free = shutil.disk_usage(path)
    usage_percent = (used / total) * 100
    return {
        'total_bytes': total,
        'used_bytes': used,
        'free_bytes': free,
        'total_gb': round(total / (1024**3), 1),
        'used_gb': round(used / (1024**3), 1),
        'free_gb': round(free / (1024**3), 1),
        'usage_percent': round(usage_percent, 1)
    }


@router.get("/system/", response_class=HTMLResponse, name="system_monitor",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def system_monitor(request: Request):
    """System monitoring page showing disk usage and ClickHouse storage."""
    try:
        # Get disk usage
        disk_info = get_disk_usage('/')

        # Get ClickHouse table sizes
        all_tables = ClickHouseClient.get_all_table_sizes()
        system_tables = ClickHouseClient.get_system_table_sizes()
        db_summary = ClickHouseClient.get_database_storage_summary()

        # Get syslogs partition info
        partitions = ClickHouseClient.get_syslogs_partition_info()

        # Get cleanup status
        cleanup_status = ClickHouseClient.get_cleanup_status()

        # Get real system partitions
        sys_partitions = get_system_partitions()

        # Calculate ClickHouse vs disk usage
        clickhouse_bytes = db_summary.get('total_bytes', 0)
        disk_used = disk_info['used_bytes']
        clickhouse_percent_of_used = round((clickhouse_bytes / disk_used * 100), 1) if disk_used > 0 else 0

        # Determine warning level
        usage_percent = disk_info['usage_percent']
        if usage_percent >= 95:
            disk_status = 'critical'
        elif usage_percent >= 90:
            disk_status = 'warning'
        elif usage_percent >= 80:
            disk_status = 'caution'
        else:
            disk_status = 'healthy'

        return _render("system/system_monitor.html", request, {
            "disk_info": disk_info,
            "disk_status": disk_status,
            "all_tables": all_tables,
            "system_tables": system_tables,
            "db_summary": db_summary,
            "partitions": partitions,
            "cleanup_status": cleanup_status,
            "clickhouse_percent_of_used": clickhouse_percent_of_used,
            "sys_partitions": sys_partitions,
            "error": None,
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return _render("system/system_monitor.html", request, {
            "disk_info": get_disk_usage('/'),
            "disk_status": 'unknown',
            "all_tables": [],
            "system_tables": [],
            "db_summary": {'databases': [], 'total_bytes': 0, 'total_readable': '0 B'},
            "partitions": [],
            "cleanup_status": {'pending_mutations': 0, 'mutations': []},
            "clickhouse_percent_of_used": 0,
            "sys_partitions": {'disks': [], 'partitions': [], 'unallocated': [], 'has_hostfs': False},
            "error": str(e),
        })


@router.post("/api/system/truncate-table/", name="truncate_system_table",
             dependencies=[Depends(require_role("ADMIN"))])
async def truncate_system_table(request: Request):
    """Truncate a system table to free up space."""
    try:
        body = await request.json()
        table = body.get('table', '')

        if not table:
            return JSONResponse({"success": False, "error": "Table name required"}, status_code=400)

        success = ClickHouseClient.truncate_system_table(table)

        if success:
            return JSONResponse({"success": True, "message": f"Truncated system.{table}"})
        else:
            return JSONResponse({"success": False, "error": f"Failed to truncate {table}"}, status_code=400)

    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/system/run-cleanup/", name="run_system_cleanup",
             dependencies=[Depends(require_role("ADMIN"))])
async def run_system_cleanup(request: Request):
    """Run the disk cleanup script manually."""
    import subprocess

    try:
        # Run cleanup script
        result = subprocess.run(
            ['/home/net/zentryc/venv/bin/python', '-m', 'fastapi_app.cli.disk_cleanup', '--threshold', '90'],
            capture_output=True,
            text=True,
            timeout=60,
            cwd='/home/net/zentryc'
        )

        return JSONResponse({
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })

    except subprocess.TimeoutExpired:
        return JSONResponse({"success": False, "error": "Cleanup script timed out"}, status_code=500)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/system/disk-usage/", name="get_disk_usage")
async def api_disk_usage():
    """API endpoint to get current disk usage."""
    try:
        disk_info = get_disk_usage('/')
        db_summary = ClickHouseClient.get_database_storage_summary()

        return JSONResponse({
            "success": True,
            "disk": disk_info,
            "clickhouse": {
                "total_bytes": db_summary['total_bytes'],
                "total_readable": db_summary['total_readable']
            }
        })
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# System Partitions / Block Devices
# ============================================================

def _format_bytes(b: int) -> str:
    """Format bytes to human-readable string."""
    if b is None:
        return "--"
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"


def get_system_partitions() -> dict:
    """Get real system block devices and partition info via lsblk + host /proc/mounts + statvfs."""
    import subprocess, json, os

    hostfs = '/hostfs'
    has_hostfs = os.path.isdir(hostfs)

    # --- Block devices from lsblk ---
    try:
        r = subprocess.run(
            ['lsblk', '-J', '-b', '-o',
             'NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,FSUSED,FSAVAIL,FSUSE%,MODEL,VENDOR'],
            capture_output=True, text=True, timeout=5
        )
        lsblk = json.loads(r.stdout) if r.stdout else {}
    except Exception:
        lsblk = {}

    # --- Read host /proc/mounts to find ALL mounted filesystems ---
    # This is critical: inside a container, lsblk can't see LVM/device-mapper mounts.
    # By reading the host's /proc/mounts we discover volumes like ubuntu--vg-ubuntu--lv.
    host_mounts = []  # list of {device, mountpoint, fstype, host_mount}
    seen_host_devs = set()
    if has_hostfs:
        try:
            with open(os.path.join(hostfs, 'proc/mounts'), 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith('/dev/'):
                        dev_path = parts[0]
                        # The mountpoint in host's /proc/mounts is relative to our /hostfs
                        container_mp = parts[1]  # e.g. /hostfs, /hostfs/boot
                        fstype = parts[2]

                        # Derive the real host mountpoint by stripping /hostfs prefix
                        if container_mp == hostfs:
                            real_mp = '/'
                        elif container_mp.startswith(hostfs + '/'):
                            real_mp = container_mp[len(hostfs):]
                        else:
                            # Skip bind-mounts to container paths (resolv.conf, hostname, etc.)
                            continue

                        # Skip duplicate mounts (same device to different bind-mount targets)
                        dev_key = dev_path + ':' + real_mp
                        if dev_key in seen_host_devs:
                            continue
                        seen_host_devs.add(dev_key)

                        # Skip non-filesystem mounts
                        if fstype in ('tmpfs', 'devtmpfs', 'proc', 'sysfs', 'cgroup', 'cgroup2',
                                      'overlay', 'devpts', 'mqueue', 'hugetlbfs', 'securityfs',
                                      'debugfs', 'tracefs', 'fusectl', 'configfs', 'pstore',
                                      'bpf', 'autofs', 'rpc_pipefs', 'nfsd', 'fuse.snapfuse'):
                            continue

                        host_mounts.append({
                            'device': dev_path,
                            'mountpoint': real_mp,
                            'fstype': fstype,
                            'container_path': container_mp,
                        })
        except Exception:
            pass

    # --- Build disk list from lsblk ---
    disks = []
    lsblk_disk_names = set()  # track which disks lsblk sees with children

    def _collect_disks(devices):
        for dev in devices:
            dtype = dev.get('type', '')
            if dtype == 'rom':
                continue
            if dtype == 'disk':
                name = dev.get('name', '')
                model = (dev.get('model') or '').strip()
                vendor = (dev.get('vendor') or '').strip()
                children = dev.get('children', [])
                fstype = dev.get('fstype') or ''
                size = dev.get('size') or 0

                has_children = len(children) > 0
                # Also check if this disk appears in host_mounts (LVM member)
                is_lvm_member = any(
                    m['device'].startswith('/dev/mapper/') for m in host_mounts
                    if m['mountpoint'] == '/'
                ) if not has_children else False

                disks.append({
                    'name': name,
                    'size': size,
                    'size_readable': _format_bytes(size),
                    'model': model,
                    'vendor': vendor,
                    'fstype': fstype,
                    'has_partitions': has_children,
                    'children_count': len(children),
                    'is_lvm_member': is_lvm_member,
                })
                if has_children:
                    lsblk_disk_names.add(name)

    _collect_disks(lsblk.get('blockdevices', []))

    # --- Build partition list from host mounts + statvfs ---
    partitions = []
    seen_partitions = set()

    for mount in host_mounts:
        dev_path = mount['device']
        real_mp = mount['mountpoint']
        fstype = mount['fstype']
        container_path = mount['container_path']

        # Deduplicate by real mountpoint
        if real_mp in seen_partitions:
            continue
        seen_partitions.add(real_mp)

        # Derive a friendly device name
        dev_name = dev_path.replace('/dev/', '').replace('mapper/', '')

        # Get real usage via statvfs
        used = None
        avail = None
        total_fs = 0
        pct = 0
        pct_str = '--'
        try:
            st = os.statvfs(container_path)
            total_fs = st.f_frsize * st.f_blocks
            free_fs = st.f_frsize * st.f_bavail
            used_fs = total_fs - free_fs
            used = used_fs
            avail = free_fs
            pct = round((used_fs / total_fs) * 100, 1) if total_fs > 0 else 0
            pct_str = f"{pct}%"
        except Exception:
            total_fs = 0

        # Find model/vendor from lsblk disks
        model = ''
        vendor = ''
        for d in disks:
            if dev_name.startswith(d['name']):
                model = d.get('model', '')
                vendor = d.get('vendor', '')
                break

        partitions.append({
            'name': dev_name,
            'type': 'lvm' if 'mapper' in dev_path else 'part',
            'mountpoint': real_mp,
            'fstype': fstype,
            'size': total_fs,
            'size_readable': _format_bytes(total_fs),
            'used': used,
            'used_readable': _format_bytes(used) if used else '--',
            'available': avail,
            'available_readable': _format_bytes(avail) if avail else '--',
            'usage_percent': pct,
            'usage_pct_str': pct_str,
            'model': model,
            'vendor': vendor,
        })

    # Sort partitions: root first, then by size descending
    partitions.sort(key=lambda p: (0 if p['mountpoint'] == '/' else 1, -(p.get('size') or 0)))

    # --- Identify unallocated disks ---
    # A disk is "unallocated" if lsblk shows it with no children AND
    # it doesn't appear in any host mount (not an LVM PV in use)
    unallocated = []
    mounted_devs = {m['device'] for m in host_mounts}

    for d in disks:
        if d['has_partitions'] or d['fstype']:
            continue
        # Check if this disk is actually used via device-mapper (LVM)
        dev_full = f"/dev/{d['name']}"
        is_used = d.get('is_lvm_member', False)
        # Also check if device appears in /proc/diskstats as an LVM PV
        if not is_used and has_hostfs:
            try:
                # Check if disk is an LVM physical volume by reading host's /proc/partitions
                pvs_path = os.path.join(hostfs, 'proc/partitions')
                with open(pvs_path) as f:
                    for line in f:
                        cols = line.split()
                        if len(cols) >= 4 and 'ubuntu' in cols[3]:
                            is_used = True
                            break
            except Exception:
                pass

        if not is_used:
            unallocated.append({
                'name': d['name'],
                'size': d['size'],
                'size_readable': d['size_readable'],
                'model': d['model'],
                'vendor': d['vendor'],
                'status': 'Unallocated',
            })
        else:
            # Mark disk as LVM member in disk info
            d['is_lvm_member'] = True

    return {
        'disks': disks,
        'partitions': partitions,
        'unallocated': unallocated,
        'has_hostfs': has_hostfs,
    }


@router.get("/api/system/partitions/", name="get_system_partitions")
async def api_system_partitions():
    """API endpoint returning real system block devices and partition info."""
    try:
        data = get_system_partitions()
        return JSONResponse({"success": True, **data})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Storage Quota Management Endpoints
# ============================================================

@router.get("/api/system/storage-settings/", name="get_storage_settings")
async def get_storage_settings(db: AsyncSession = Depends(get_db)):
    """Get current storage settings."""
    from sqlalchemy import select
    from ..models.storage_settings import StorageSettings

    try:
        # Get or create default settings
        result = await db.execute(select(StorageSettings).limit(1))
        settings = result.scalar_one_or_none()

        if not settings:
            # Create default settings
            settings = StorageSettings(
                syslogs_max_size_gb=600.0,
                auto_cleanup_enabled=True,
                cleanup_trigger_percent=95.0,
                cleanup_target_percent=80.0,
                min_retention_days=7,
                disk_warning_percent=85.0,
                disk_critical_percent=95.0,
                monitor_interval_minutes=15
            )
            db.add(settings)
            await db.commit()
            await db.refresh(settings)

        # Get current syslogs storage info
        syslogs_info = ClickHouseClient.get_syslogs_storage_info()

        return JSONResponse({
            "success": True,
            "settings": {
                "id": settings.id,
                "syslogs_max_size_gb": settings.syslogs_max_size_gb,
                "auto_cleanup_enabled": settings.auto_cleanup_enabled,
                "cleanup_trigger_percent": settings.cleanup_trigger_percent,
                "cleanup_target_percent": settings.cleanup_target_percent,
                "min_retention_days": settings.min_retention_days,
                "disk_warning_percent": settings.disk_warning_percent,
                "disk_critical_percent": settings.disk_critical_percent,
                "monitor_interval_minutes": settings.monitor_interval_minutes,
                "last_cleanup_at": settings.last_cleanup_at.isoformat() if settings.last_cleanup_at else None,
                "last_cleanup_freed_gb": settings.last_cleanup_freed_gb,
                "last_cleanup_status": settings.last_cleanup_status,
                "current_size_gb": settings.current_size_gb,
                "usage_percent": settings.usage_percent,
                "needs_cleanup": settings.needs_cleanup
            },
            "current_storage": syslogs_info
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/system/storage-settings/", name="update_storage_settings",
             dependencies=[Depends(require_role("ADMIN"))])
async def update_storage_settings(request: Request, db: AsyncSession = Depends(get_db)):
    """Update storage settings."""
    from sqlalchemy import select
    from ..models.storage_settings import StorageSettings

    try:
        body = await request.json()

        result = await db.execute(select(StorageSettings).limit(1))
        settings = result.scalar_one_or_none()

        if not settings:
            settings = StorageSettings()
            db.add(settings)

        # Update allowed fields
        allowed_fields = [
            'syslogs_max_size_gb', 'auto_cleanup_enabled', 'cleanup_trigger_percent',
            'cleanup_target_percent', 'min_retention_days', 'disk_warning_percent',
            'disk_critical_percent', 'monitor_interval_minutes'
        ]

        for field in allowed_fields:
            if field in body:
                setattr(settings, field, body[field])

        await db.commit()
        await db.refresh(settings)

        return JSONResponse({
            "success": True,
            "message": "Storage settings updated successfully",
            "settings": {
                "syslogs_max_size_gb": settings.syslogs_max_size_gb,
                "auto_cleanup_enabled": settings.auto_cleanup_enabled,
                "cleanup_trigger_percent": settings.cleanup_trigger_percent,
                "cleanup_target_percent": settings.cleanup_target_percent,
                "min_retention_days": settings.min_retention_days
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/system/trigger-cleanup/", name="trigger_manual_cleanup",
             dependencies=[Depends(require_role("ADMIN"))])
async def trigger_manual_cleanup(request: Request, db: AsyncSession = Depends(get_db)):
    """Manually trigger storage cleanup based on current settings."""
    from sqlalchemy import select
    from datetime import datetime, timezone
    from ..models.storage_settings import StorageSettings, StorageCleanupLog

    try:
        body = await request.json() if request.headers.get('content-type') == 'application/json' else {}
        force = body.get('force', False)

        # Get settings
        result = await db.execute(select(StorageSettings).limit(1))
        settings = result.scalar_one_or_none()

        if not settings:
            return JSONResponse({
                "success": False,
                "error": "Storage settings not configured. Please configure settings first."
            }, status_code=400)

        # Get current storage info
        syslogs_info = ClickHouseClient.get_syslogs_storage_info()
        current_size_gb = syslogs_info['size_gb']

        # Check if cleanup is needed
        target_size_gb = settings.syslogs_max_size_gb * (settings.cleanup_target_percent / 100)

        if not force and current_size_gb <= settings.syslogs_max_size_gb:
            return JSONResponse({
                "success": True,
                "message": f"No cleanup needed. Current size ({current_size_gb:.2f} GB) is within quota ({settings.syslogs_max_size_gb:.2f} GB)",
                "cleanup_performed": False,
                "current_size_gb": current_size_gb,
                "quota_gb": settings.syslogs_max_size_gb
            })

        # Create cleanup log entry
        cleanup_log = StorageCleanupLog(
            triggered_by='manual',
            trigger_reason=f"Manual trigger (force={force}). Size: {current_size_gb:.2f} GB, Quota: {settings.syslogs_max_size_gb:.2f} GB",
            size_before_gb=current_size_gb,
            rows_before=syslogs_info['total_rows'],
            status='started'
        )
        db.add(cleanup_log)
        await db.commit()
        await db.refresh(cleanup_log)

        # Execute cleanup
        cleanup_result = ClickHouseClient.delete_logs_to_reach_target_size(
            target_size_gb=target_size_gb,
            min_retention_days=settings.min_retention_days
        )

        # Update cleanup log
        cleanup_log.status = 'success' if cleanup_result['success'] else 'failed'
        cleanup_log.error_message = cleanup_result.get('message')
        cleanup_log.completed_at = datetime.now(timezone.utc)
        cleanup_log.duration_seconds = (cleanup_log.completed_at - cleanup_log.started_at).total_seconds()

        if cleanup_result.get('action_taken'):
            cleanup_log.deletion_query = f"DELETE WHERE timestamp < now() - INTERVAL {cleanup_result.get('retention_days_used', 0)} DAY"

        # Update settings with last cleanup info
        settings.last_cleanup_at = datetime.now(timezone.utc)
        settings.last_cleanup_status = cleanup_log.status
        settings.last_cleanup_freed_gb = cleanup_result.get('estimated_freed_gb', 0)
        settings.last_cleanup_rows_deleted = cleanup_result.get('rows_affected', 0)
        settings.current_size_gb = current_size_gb
        settings.current_rows = syslogs_info['total_rows']
        settings.last_monitored_at = datetime.now(timezone.utc)

        await db.commit()

        return JSONResponse({
            "success": cleanup_result['success'],
            "message": cleanup_result['message'],
            "cleanup_performed": cleanup_result.get('action_taken', False),
            "details": {
                "size_before_gb": current_size_gb,
                "target_size_gb": target_size_gb,
                "estimated_freed_gb": cleanup_result.get('estimated_freed_gb', 0),
                "rows_affected": cleanup_result.get('rows_affected', 0),
                "retention_days_used": cleanup_result.get('retention_days_used'),
                "mutation_id": cleanup_result.get('mutation_id')
            }
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/system/storage-status/", name="get_storage_status")
async def get_storage_status(db: AsyncSession = Depends(get_db)):
    """Get comprehensive storage status including quota usage and recommendations."""
    from sqlalchemy import select
    from ..models.storage_settings import StorageSettings

    try:
        # Get settings
        result = await db.execute(select(StorageSettings).limit(1))
        settings = result.scalar_one_or_none()

        # Get current storage info
        syslogs_info = ClickHouseClient.get_syslogs_storage_info()
        disk_info = get_disk_usage('/')
        cleanup_status = ClickHouseClient.get_cleanup_status()

        current_size_gb = syslogs_info['size_gb']
        quota_gb = settings.syslogs_max_size_gb if settings else 600.0

        # Calculate status
        usage_percent = (current_size_gb / quota_gb * 100) if quota_gb > 0 else 0

        if usage_percent >= 95:
            status = 'critical'
            status_message = 'Storage quota critically exceeded! Immediate cleanup required.'
        elif usage_percent >= 85:
            status = 'warning'
            status_message = 'Storage approaching quota limit. Cleanup recommended.'
        elif usage_percent >= 70:
            status = 'caution'
            status_message = 'Storage usage is moderate.'
        else:
            status = 'healthy'
            status_message = 'Storage usage is within healthy limits.'

        # Estimate how long until quota is reached (based on simple projection)
        # This would need historical data for accurate prediction
        oldest_log_days = ClickHouseClient.get_oldest_log_age_days()

        return JSONResponse({
            "success": True,
            "status": status,
            "status_message": status_message,
            "quota": {
                "max_size_gb": quota_gb,
                "current_size_gb": current_size_gb,
                "usage_percent": round(usage_percent, 1),
                "free_quota_gb": round(quota_gb - current_size_gb, 2),
                "auto_cleanup_enabled": settings.auto_cleanup_enabled if settings else True
            },
            "syslogs": {
                "total_rows": syslogs_info['total_rows'],
                "size_readable": syslogs_info['size_readable'],
                "oldest_data": syslogs_info['oldest_data'].isoformat() if syslogs_info['oldest_data'] else None,
                "newest_data": syslogs_info['newest_data'].isoformat() if syslogs_info['newest_data'] else None,
                "oldest_log_days": oldest_log_days
            },
            "disk": disk_info,
            "pending_mutations": cleanup_status['pending_mutations'],
            "last_cleanup": {
                "at": settings.last_cleanup_at.isoformat() if settings and settings.last_cleanup_at else None,
                "status": settings.last_cleanup_status if settings else None,
                "freed_gb": settings.last_cleanup_freed_gb if settings else None
            }
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/system/cleanup-history/", name="get_cleanup_history")
async def get_cleanup_history(db: AsyncSession = Depends(get_db), limit: int = 20):
    """Get history of cleanup operations."""
    from sqlalchemy import select
    from ..models.storage_settings import StorageCleanupLog

    try:
        result = await db.execute(
            select(StorageCleanupLog)
            .order_by(StorageCleanupLog.started_at.desc())
            .limit(limit)
        )
        logs = result.scalars().all()

        return JSONResponse({
            "success": True,
            "history": [
                {
                    "id": log.id,
                    "triggered_by": log.triggered_by,
                    "trigger_reason": log.trigger_reason,
                    "size_before_gb": log.size_before_gb,
                    "size_after_gb": log.size_after_gb,
                    "rows_before": log.rows_before,
                    "rows_after": log.rows_after,
                    "status": log.status,
                    "error_message": log.error_message,
                    "started_at": log.started_at.isoformat() if log.started_at else None,
                    "completed_at": log.completed_at.isoformat() if log.completed_at else None,
                    "duration_seconds": log.duration_seconds
                }
                for log in logs
            ]
        })

    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/system/estimate-cleanup/", name="estimate_cleanup")
async def estimate_cleanup(request: Request):
    """Estimate the impact of cleanup with different retention days."""
    try:
        body = await request.json()
        days = body.get('days', 30)

        if days < 1:
            return JSONResponse({"success": False, "error": "Days must be at least 1"}, status_code=400)

        estimate = ClickHouseClient.estimate_deletion_size(days)
        current_info = ClickHouseClient.get_syslogs_storage_info()

        return JSONResponse({
            "success": True,
            "retention_days": days,
            "estimate": {
                "rows_to_delete": estimate['rows_to_delete'],
                "estimated_bytes": estimate['estimated_bytes'],
                "estimated_gb": estimate['estimated_gb'],
                "percent_of_total": round((estimate['rows_to_delete'] / current_info['total_rows'] * 100), 1) if current_info['total_rows'] > 0 else 0
            },
            "current_storage": {
                "total_rows": current_info['total_rows'],
                "size_gb": current_info['size_gb'],
                "remaining_after_cleanup_gb": round(current_info['size_gb'] - estimate['estimated_gb'], 2)
            }
        })

    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ============================================================
# Audit Log Viewer (Admin Only)
# ============================================================

@router.get("/system/audit-log/", response_class=HTMLResponse, name="audit_log",
            dependencies=[Depends(require_role("ADMIN"))])
async def audit_log(
    request: Request,
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=200),
):
    """Audit log viewer page."""
    from ..services.audit_service import get_audit_logs, get_distinct_values

    start_time = None
    end_time = None
    if start_date:
        try:
            start_time = datetime.fromisoformat(start_date)
        except ValueError:
            pass
    if end_date:
        try:
            end_time = datetime.fromisoformat(end_date + "T23:59:59")
        except ValueError:
            pass

    offset = (page - 1) * per_page

    logs, total = get_audit_logs(
        limit=per_page,
        offset=offset,
        username=username or None,
        action=action or None,
        resource_type=resource_type or None,
        start_time=start_time,
        end_time=end_time,
    )

    total_pages = max(1, (total + per_page - 1) // per_page)

    # Get distinct values for filter dropdowns
    usernames = get_distinct_values("username")
    actions = get_distinct_values("action")
    resource_types = get_distinct_values("resource_type")

    return _render("system/audit_log.html", request, {
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "usernames": usernames,
        "actions": actions,
        "resource_types": resource_types,
        "current_username": username or "",
        "current_action": action or "",
        "current_resource_type": resource_type or "",
        "current_start_date": start_date or "",
        "current_end_date": end_date or "",
    })


@router.get("/api/system/audit-log/export/", name="audit_log_export",
            dependencies=[Depends(require_role("ADMIN"))])
async def audit_log_export(
    request: Request,
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
):
    """Export audit logs as CSV."""
    from ..services.audit_service import export_csv
    from fastapi.responses import Response

    start_time = None
    end_time = None
    if start_date:
        try:
            start_time = datetime.fromisoformat(start_date)
        except ValueError:
            pass
    if end_date:
        try:
            end_time = datetime.fromisoformat(end_date + "T23:59:59")
        except ValueError:
            pass

    csv_data = export_csv(
        username=username or None,
        action=action or None,
        resource_type=resource_type or None,
        start_time=start_time,
        end_time=end_time,
    )

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


# ============================================================
# NQL (Zentryc Query Language) API
# ============================================================

@router.post("/api/nql/validate", dependencies=[Depends(require_min_role("VIEWER"))])
async def nql_validate(request: Request):
    """Validate an NQL query without executing it."""
    from ..services.nql_parser import validate_nql
    data = await request.json()
    query_text = data.get("query", "")
    is_valid, error = validate_nql(query_text)
    return {"valid": is_valid, "error": error}


@router.post("/api/nql/query", dependencies=[Depends(require_min_role("VIEWER"))])
async def nql_query(request: Request):
    """Execute an NQL query and return results."""
    from ..services.nql_parser import compile_nql, NQLSyntaxError

    data = await request.json()
    query_text = data.get("query", "")
    time_range = data.get("time_range", "1h")
    page = max(1, data.get("page", 1))
    per_page = min(200, max(10, data.get("per_page", 100)))

    if not query_text.strip():
        return JSONResponse(status_code=400, content={"detail": "Query is required"})

    try:
        compiled = compile_nql(query_text)
    except NQLSyntaxError as e:
        return JSONResponse(status_code=400, content={"detail": str(e), "type": "syntax_error"})

    # Build time filter
    time_map = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080, "30d": 43200}
    minutes = time_map.get(time_range, 60)
    time_filter = f"timestamp > now() - INTERVAL {minutes} MINUTE"

    loop = asyncio.get_event_loop()

    def _run_query(sql_text):
        """Run a ClickHouse query with a fresh client to avoid concurrency issues."""
        c = ClickHouseClient.get_client()
        return c.query(sql_text)

    try:
        if compiled["is_aggregate"]:
            # Aggregate query
            select_clause = compiled["select"] or "count() as count"
            group_by = f"GROUP BY {compiled['group_by']}" if compiled["group_by"] else ""
            having = f"HAVING {compiled['having']}" if compiled["having"] else ""
            order_by = f"ORDER BY {compiled['order_by']}" if compiled["order_by"] else ""
            limit_val = compiled["limit"] or per_page

            sql = f"""SELECT {select_clause}
FROM syslogs
PREWHERE {time_filter}
WHERE {compiled['where']}
{group_by}
{having}
{order_by}
LIMIT {limit_val}"""

            result = await loop.run_in_executor(_executor, lambda: _run_query(sql))
            columns = result.column_names
            rows = []
            for row in result.result_rows:
                rows.append({columns[i]: _serialize_value(row[i]) for i in range(len(columns))})

            return {
                "type": "aggregate",
                "columns": columns,
                "rows": rows,
                "total": len(rows),
                "sql": sql,
            }
        else:
            # Regular query
            offset = (page - 1) * per_page
            order_by = f"ORDER BY {compiled['order_by']}" if compiled["order_by"] else "ORDER BY timestamp DESC"
            limit_val = compiled["limit"] or per_page

            columns_str = ClickHouseClient.LIGHT_COLUMNS

            sql = f"""SELECT {columns_str}
FROM syslogs
PREWHERE {time_filter}
WHERE {compiled['where']}
{order_by}
LIMIT {limit_val} OFFSET {offset}"""

            count_sql = f"""SELECT count()
FROM syslogs
PREWHERE {time_filter}
WHERE {compiled['where']}"""

            result_future = loop.run_in_executor(_executor, lambda: list(_run_query(sql).named_results()))
            count_future = loop.run_in_executor(_executor, lambda: _run_query(count_sql).result_rows[0][0])

            logs, total = await asyncio.gather(result_future, count_future)

            # Serialize results
            serialized = []
            for log in logs:
                row = {}
                for k, v in log.items():
                    row[k] = _serialize_value(v)
                serialized.append(row)

            return {
                "type": "logs",
                "rows": serialized,
                "total": total,
                "page": page,
                "per_page": per_page,
                "sql": sql,
            }

    except Exception as e:
        logger.error(f"NQL query error: {e}")
        return JSONResponse(status_code=400, content={"detail": f"Query execution error: {str(e)}"})


@router.get("/api/nql/fields", dependencies=[Depends(require_min_role("VIEWER"))])
async def nql_fields():
    """Return field metadata for NQL autocomplete."""
    from ..services.nql_parser import FIELD_METADATA
    return {"fields": FIELD_METADATA}


def _serialize_value(v):
    """Serialize a ClickHouse value to JSON-safe format."""
    from datetime import datetime as dt
    from ipaddress import IPv4Address, IPv6Address
    if isinstance(v, (dt, datetime)):
        return v.isoformat()
    if isinstance(v, (IPv4Address, IPv6Address)):
        return str(v)
    if isinstance(v, dict):
        return {k: _serialize_value(val) for k, val in v.items()}
    return v
