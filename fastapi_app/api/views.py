"""
HTML view routes for the web UI.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, DeviceStatus, ParserType, RetentionDays
from ..models.credential import DeviceCredential, CredentialType, DeviceVdom
from ..models.device_ssh_settings import DeviceSshSettings
from ..models.routing import RoutingTableSnapshot, RoutingEntry, RouteChange
from ..models.zone import ZoneSnapshot, ZoneEntry, InterfaceEntry

# Thread pool for running blocking ClickHouse queries in parallel
_executor = ThreadPoolExecutor(max_workers=4)

router = APIRouter(tags=["views"])

templates = Jinja2Templates(directory="fastapi_app/templates")


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
    """Dashboard view with comprehensive SIEM statistics."""
    try:
        # Get comprehensive dashboard stats
        stats = ClickHouseClient.get_dashboard_stats()

        # Get recent logs (limit to 20 for quick display)
        logs = ClickHouseClient.get_recent_logs(limit=20)

        # Prepare severity data for chart
        severity_data = []
        for item in stats.get('severity_breakdown', []):
            severity_data.append({
                'name': SEVERITY_MAP.get(item['severity'], f"Level {item['severity']}"),
                'count': item['count'],
                'severity': item['severity']
            })

        # Prepare hourly timeline data (24h)
        timeline_labels = []
        timeline_data = []
        timeline_critical = []
        timeline_denied = []
        for item in stats.get('traffic_timeline', []):
            hour = item.get('hour')
            if hasattr(hour, 'strftime'):
                timeline_labels.append(hour.strftime('%H:%M'))
            else:
                timeline_labels.append(str(hour))
            timeline_data.append(item.get('total', 0))
            timeline_critical.append(item.get('critical', 0))
            timeline_denied.append(item.get('denied', 0))

        # Prepare realtime traffic (per minute, last hour)
        realtime_labels = []
        realtime_data = []
        for item in stats.get('realtime_traffic', []):
            minute = item.get('minute')
            if hasattr(minute, 'strftime'):
                realtime_labels.append(minute.strftime('%H:%M'))
            else:
                realtime_labels.append(str(minute))
            realtime_data.append(item.get('count', 0))

        # Prepare action distribution data
        action_data = []
        for item in stats.get('action_breakdown', []):
            action_data.append({
                'action': item.get('action_type', 'unknown'),
                'count': item.get('count', 0)
            })

        # Prepare protocol distribution
        protocol_data = []
        for item in stats.get('protocol_distribution', []):
            protocol_data.append({
                'protocol': item.get('protocol', 'Unknown'),
                'count': item.get('count', 0)
            })

        # Port service mapping for common ports
        port_services = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }

        return templates.TemplateResponse("logs/dashboard.html", {
            "request": request,
            "logs": logs,
            "severity_map": SEVERITY_MAP,
            "stats": stats,
            "severity_data": severity_data,
            "timeline_labels": timeline_labels,
            "timeline_data": timeline_data,
            "timeline_critical": timeline_critical,
            "timeline_denied": timeline_denied,
            "realtime_labels": realtime_labels,
            "realtime_data": realtime_data,
            "action_data": action_data,
            "protocol_data": protocol_data,
            "port_services": port_services,
            "error": None,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return templates.TemplateResponse("logs/dashboard.html", {
            "request": request,
            "logs": [],
            "severity_map": SEVERITY_MAP,
            "stats": {},
            "severity_data": [],
            "timeline_labels": [],
            "timeline_data": [],
            "timeline_critical": [],
            "timeline_denied": [],
            "realtime_labels": [],
            "realtime_data": [],
            "action_data": [],
            "protocol_data": [],
            "port_services": {},
            "error": str(e),
        })


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
    # New direct filter parameters for simplified search
    srcip: Optional[str] = Query(None),
    dstip: Optional[str] = Query(None),
    dstport: Optional[str] = Query(None),
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
        now = datetime.now()

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

        # Handle srcip parameter
        srcip_clean = srcip.strip() if srcip and srcip.strip() else None
        if srcip_clean:
            search_parts.append(f"srcip:{srcip_clean}")

        # Handle dstip parameter
        dstip_clean = dstip.strip() if dstip and dstip.strip() else None
        if dstip_clean:
            search_parts.append(f"dstip:{dstip_clean}")

        # Handle dstport parameter
        dstport_clean = dstport.strip() if dstport and dstport.strip() else None
        if dstport_clean:
            search_parts.append(f"dstport:{dstport_clean}")

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

        # Run all ClickHouse queries in parallel for better performance
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
        logs, total, stats, devices = await asyncio.gather(
            logs_future, total_future, stats_future, devices_future
        )

        # Handle approximate count (-1 means 100,000+)
        is_approximate = total == -1
        if is_approximate:
            total = 100000  # Use 100,000 for pagination calculation
            total_display = "100,000+"
        else:
            total_display = f"{total:,}"

        total_pages = (total + per_page_num - 1) // per_page_num if total > 0 else 1

        # Clean up filter values for template (handle empty strings)
        current_device = device if device and device.strip() else None
        current_action = action if action and action.strip() else None
        current_q = q if q and q.strip() else None

        return templates.TemplateResponse("logs/log_list.html", {
            "request": request,
            "logs": logs,
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
            # New direct filter values
            "current_srcip": srcip_clean,
            "current_dstip": dstip_clean,
            "current_dstport": dstport_clean,
            "error": None,
        })
    except Exception as e:
        import traceback
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in log_list view: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        print(f"ERROR in log_list: {type(e).__name__}: {e}")
        print(traceback.format_exc())
        return templates.TemplateResponse("logs/log_list.html", {
            "request": request,
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
            "current_srcip": srcip if srcip else None,
            "current_dstip": dstip if dstip else None,
            "current_dstport": dstport if dstport else None,
            "error": str(e),
        })


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
        now = datetime.now()

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

        # Handle srcip parameter
        srcip_clean = srcip.strip() if srcip and srcip.strip() else None
        if srcip_clean:
            search_parts.append(f"srcip:{srcip_clean}")

        # Handle dstip parameter
        dstip_clean = dstip.strip() if dstip and dstip.strip() else None
        if dstip_clean:
            search_parts.append(f"dstip:{dstip_clean}")

        # Handle dstport parameter
        dstport_clean = dstport.strip() if dstport and dstport.strip() else None
        if dstport_clean:
            search_parts.append(f"dstport:{dstport_clean}")

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

        return templates.TemplateResponse("logs/policy_builder.html", {
            "request": request,
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
            "error": None,
        })
    except Exception as e:
        import traceback
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in policy_builder view: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        return templates.TemplateResponse("logs/policy_builder.html", {
            "request": request,
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
            "error": str(e),
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

        return templates.TemplateResponse("devices/device_list.html", {
            "request": request,
            "devices": devices,
            "storage_stats": storage_stats,
            "device_storage_map": device_storage_map,
            "format_bytes": format_bytes,
            "format_number": format_number,
        })
    except Exception as e:
        return templates.TemplateResponse("devices/device_list.html", {
            "request": request,
            "devices": [],
            "storage_stats": {},
            "device_storage_map": {},
            "format_bytes": format_bytes,
            "format_number": format_number,
            "error": str(e),
        })


@router.get("/devices/{device_id}/edit/", response_class=HTMLResponse, name="edit_device")
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

    return templates.TemplateResponse("devices/edit_device.html", {
        "request": request,
        "device": device,
        "parser_choices": ParserType.CHOICES,
        "retention_choices": RetentionDays.CHOICES,
        "current_vdom": current_vdom,
        "ssh_host": ssh_host,
    })


@router.post("/devices/{device_id}/edit/", name="edit_device_post")
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


@router.get("/devices/{device_id}/approve/", name="approve_device_view")
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


@router.get("/devices/{device_id}/reject/", name="reject_device_view")
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

    # Check if device has active SSH credentials
    active_cred_result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type == 'SSH'
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

    # Validate and default current tab
    valid_tabs = ['routes', 'zones', 'changes', 'snapshots']
    current_tab = tab if tab in valid_tabs else 'routes'

    return templates.TemplateResponse("devices/device_detail.html", {
        "request": request,
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
        "current_tab": current_tab,
    })


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

    # Get active SSH credential
    cred_result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type == 'SSH'
        )
        .limit(1)
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        return JSONResponse({"success": False, "message": "No SSH credentials configured"})

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

    # Get active SSH credential
    cred_result = await db.execute(
        select(DeviceCredential)
        .where(
            DeviceCredential.device_id == device_id,
            DeviceCredential.is_active == True,
            DeviceCredential.credential_type == 'SSH'
        )
        .limit(1)
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        return JSONResponse({"success": False, "message": "No SSH credentials configured"})

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


# ============================================================
# Device Credentials Endpoints
# ============================================================

@router.get("/devices/{device_id}/credentials/", response_class=HTMLResponse, name="device_credentials")
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

    return templates.TemplateResponse("devices/device_credentials.html", {
        "request": request,
        "device": device,
        "credentials": credentials,
        "credential_types": CredentialType.CHOICES,
        "vdoms": vdoms,
    })


@router.post("/devices/{device_id}/credentials/add/", name="add_credential")
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


@router.post("/devices/{device_id}/credentials/update/", name="update_credential")
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


@router.post("/devices/{device_id}/credentials/{credential_id}/delete/", name="delete_credential")
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


@router.post("/devices/{device_id}/credentials/{credential_id}/test/", name="test_credential")
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

    ssh_host = device.ip_address
    ssh_host_result = await db.execute(
        select(DeviceSshSettings.ssh_host)
        .where(DeviceSshSettings.device_id == device_id)
        .limit(1)
    )
    ssh_host_override = ssh_host_result.scalar_one_or_none()
    if ssh_host_override:
        ssh_host = ssh_host_override.strip() or ssh_host

    # Test connection in thread pool (blocking operation)
    loop = asyncio.get_event_loop()
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

    return JSONResponse({
        "success": result.success,
        "message": result.error if not result.success else "Connection successful",
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

        # Build the policy CLI
        result = PolicyBuilderService.build_policy_from_log(
            log_data=log_data,
            zone_table=zone_table,
            vdom=vdom,
            custom_name=policy_name,
            vendor=vendor
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
