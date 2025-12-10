"""
HTML view routes for the web UI.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, DeviceStatus, ParserType, RetentionDays

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
    """Dashboard view with overview statistics."""
    try:
        # Get recent logs
        logs = ClickHouseClient.get_recent_logs(limit=50)

        # Get stats
        stats = ClickHouseClient.get_stats()

        # Prepare severity data for chart
        severity_data = []
        for sev, count in stats.get('severity', []):
            severity_data.append({
                'name': SEVERITY_MAP.get(sev, f'Level {sev}'),
                'count': count
            })

        # Prepare timeline data
        timeline_labels = []
        timeline_data = []
        for timestamp, count in stats.get('traffic', []):
            if hasattr(timestamp, 'strftime'):
                timeline_labels.append(timestamp.strftime('%H:%M'))
            else:
                timeline_labels.append(str(timestamp))
            timeline_data.append(count)

        return templates.TemplateResponse("logs/dashboard.html", {
            "request": request,
            "logs": logs,
            "severity_map": SEVERITY_MAP,
            "severity_data": severity_data,
            "timeline_labels": timeline_labels,
            "timeline_data": timeline_data,
            "error": None,
        })
    except Exception as e:
        return templates.TemplateResponse("logs/dashboard.html", {
            "request": request,
            "logs": [],
            "severity_map": SEVERITY_MAP,
            "severity_data": [],
            "timeline_labels": [],
            "timeline_data": [],
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

    return templates.TemplateResponse("devices/edit_device.html", {
        "request": request,
        "device": device,
        "parser_choices": ParserType.CHOICES,
        "retention_choices": RetentionDays.CHOICES,
    })


@router.post("/devices/{device_id}/edit/", name="edit_device_post")
async def edit_device_post(
    device_id: int,
    hostname: str = Form(""),
    parser: str = Form("GENERIC"),
    retention_days: int = Form(90),
    db: AsyncSession = Depends(get_db),
):
    """Handle device edit form submission."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if device:
        device.hostname = hostname or None
        device.parser = parser
        device.retention_days = retention_days
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
