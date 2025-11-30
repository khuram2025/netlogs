"""
Logs API endpoints for log search and dashboard.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Query, HTTPException

from ..db.clickhouse import ClickHouseClient
from ..schemas.logs import (
    LogEntry,
    LogSearchParams,
    LogSearchResponse,
    LogStats,
    DashboardStats,
    StorageStats,
)

router = APIRouter(prefix="/logs", tags=["logs"])


# Severity mapping
SEVERITY_NAMES = {
    0: 'Emergency',
    1: 'Alert',
    2: 'Critical',
    3: 'Error',
    4: 'Warning',
    5: 'Notice',
    6: 'Info',
    7: 'Debug'
}

SEVERITY_CLASSES = {
    0: 'critical',
    1: 'critical',
    2: 'critical',
    3: 'error',
    4: 'warning',
    5: 'notice',
    6: 'info',
    7: 'debug'
}


def format_log_entry(log: Dict[str, Any]) -> Dict[str, Any]:
    """Format log entry for API response."""
    severity = log.get('severity', 6)
    return {
        **log,
        'device_ip': str(log.get('device_ip', '')),
        'severity_name': SEVERITY_NAMES.get(severity, 'Unknown'),
        'severity_class': SEVERITY_CLASSES.get(severity, 'info'),
    }


@router.get("/search", response_model=LogSearchResponse)
async def search_logs(
    device: Optional[str] = Query(None, description="Device IP to filter"),
    severity: Optional[int] = Query(None, ge=0, le=7, description="Severity level"),
    facility: Optional[int] = Query(None, ge=0, le=23, description="Facility code"),
    q: Optional[str] = Query(None, description="Search query"),
    start: Optional[datetime] = Query(None, description="Start time"),
    end: Optional[datetime] = Query(None, description="End time"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """Search logs with advanced filtering."""
    try:
        device_ips = [device] if device else None
        severities = [severity] if severity is not None else None
        facilities = [facility] if facility is not None else None

        logs = ClickHouseClient.search_logs(
            limit=limit,
            offset=offset,
            device_ips=device_ips,
            severities=severities,
            start_time=start,
            end_time=end,
            query_text=q,
            facilities=facilities,
        )

        total = ClickHouseClient.count_logs(
            device_ips=device_ips,
            severities=severities,
            start_time=start,
            end_time=end,
            query_text=q,
            facilities=facilities,
        )

        formatted_logs = [format_log_entry(log) for log in logs]

        return LogSearchResponse(
            logs=formatted_logs,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(logs)) < total,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
async def get_recent_logs(
    limit: int = Query(50, ge=1, le=500, description="Number of logs to return"),
):
    """Get most recent logs."""
    try:
        logs = ClickHouseClient.get_recent_logs(limit=limit)
        return [format_log_entry(log) for log in logs]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_log_stats(
    device: Optional[str] = Query(None, description="Device IP to filter"),
    start: Optional[datetime] = Query(None, description="Start time"),
    end: Optional[datetime] = Query(None, description="End time"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Get log statistics summary."""
    try:
        device_ips = [device] if device else None

        stats = ClickHouseClient.get_log_stats_summary(
            device_ips=device_ips,
            start_time=start,
            end_time=end,
            query_text=q,
        )

        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_dashboard_stats():
    """Get dashboard statistics."""
    try:
        # Recent logs
        recent_logs = ClickHouseClient.get_recent_logs(limit=50)

        # Severity distribution
        severity_dist = ClickHouseClient.get_severity_distribution(hours=24)
        severity_counts = {}
        for row in severity_dist:
            sev = row.get('severity', 6)
            severity_counts[SEVERITY_NAMES.get(sev, 'Unknown')] = row.get('count', 0)

        # Traffic timeline
        traffic = ClickHouseClient.get_traffic_timeline(hours=1)
        traffic_timeline = [
            {
                'time': row['minute'].isoformat() if hasattr(row['minute'], 'isoformat') else str(row['minute']),
                'count': row['count']
            }
            for row in traffic
        ]

        # Totals
        total_logs_24h = ClickHouseClient.get_total_logs_24h()
        unique_devices = ClickHouseClient.get_unique_devices_count()

        return DashboardStats(
            recent_logs=[format_log_entry(log) for log in recent_logs],
            severity_counts=severity_counts,
            traffic_timeline=traffic_timeline,
            total_logs_24h=total_logs_24h,
            unique_devices=unique_devices,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage")
async def get_storage_stats():
    """Get storage statistics."""
    try:
        stats = ClickHouseClient.get_storage_stats()

        return StorageStats(
            total_rows=stats.get('total_rows', 0),
            total_bytes=stats.get('uncompressed_bytes', 0),
            compressed_bytes=stats.get('compressed_bytes', 0),
            total_display=stats.get('uncompressed_size', '0 B'),
            compressed_display=stats.get('compressed_size', '0 B'),
            compression_ratio=stats.get('compression_ratio', 0),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices")
async def get_log_devices():
    """Get list of devices that have sent logs."""
    try:
        devices = ClickHouseClient.get_distinct_devices()
        return {"devices": devices}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/severity-distribution")
async def get_severity_distribution(
    hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
):
    """Get severity distribution for the specified time period."""
    try:
        dist = ClickHouseClient.get_severity_distribution(hours=hours)
        result = {}
        for row in dist:
            sev = row.get('severity', 6)
            result[SEVERITY_NAMES.get(sev, f'Severity {sev}')] = row.get('count', 0)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device-counts")
async def get_device_log_counts(
    hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
):
    """Get log counts per device."""
    try:
        counts = ClickHouseClient.get_device_log_counts(hours=hours)
        return counts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/traffic-timeline")
async def get_traffic_timeline(
    hours: int = Query(1, ge=1, le=24, description="Hours to look back"),
):
    """Get traffic timeline for charts."""
    try:
        traffic = ClickHouseClient.get_traffic_timeline(hours=hours)
        return [
            {
                'time': row['minute'].isoformat() if hasattr(row['minute'], 'isoformat') else str(row['minute']),
                'count': row['count']
            }
            for row in traffic
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage-timeline")
async def get_storage_timeline(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
):
    """Get storage timeline for charts."""
    try:
        storage = ClickHouseClient.get_storage_by_time_range(hours=hours)
        return [
            {
                'hour': row['hour'].isoformat() if hasattr(row['hour'], 'isoformat') else str(row['hour']),
                'log_count': row['log_count'],
                'raw_bytes': row['raw_bytes'],
            }
            for row in storage
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/session-flow")
async def get_session_flow(
    timestamp: str = Query(..., description="Log timestamp in ISO format"),
    device: str = Query(..., description="Device IP that logged the entry"),
    window: int = Query(10, ge=1, le=60, description="Time window in seconds to search for related logs"),
):
    """
    Get session flow across multiple firewalls.

    This endpoint traces a network session across all firewalls that logged it,
    showing the complete packet flow path from source to destination.

    The correlation is based on:
    - Source IP
    - Destination IP
    - Destination Port
    - Protocol
    - Time window (±N seconds)

    Returns:
    - original_log: The log entry you queried for
    - flow: All related log entries from all firewalls, ordered by time
    - summary: Summary including firewall count, whether all allowed, etc.
    """
    try:
        result = ClickHouseClient.get_session_flow_by_log(
            log_timestamp=timestamp,
            device_ip=device,
            time_window_seconds=window
        )

        if not result.get('original_log'):
            raise HTTPException(status_code=404, detail="Log entry not found")

        # Format timestamps for JSON serialization
        def format_flow_entry(entry):
            formatted = {**entry}
            if 'timestamp' in formatted and hasattr(formatted['timestamp'], 'isoformat'):
                formatted['timestamp'] = formatted['timestamp'].isoformat()
            return formatted

        return {
            'original_log': format_flow_entry(result['original_log']) if result.get('original_log') else None,
            'flow': [format_flow_entry(f) for f in result.get('flow', [])],
            'summary': result.get('summary', {})
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
