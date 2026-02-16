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


# Search field definitions for autocomplete
SEARCH_FIELDS = {
    # Source fields
    'srcip': {
        'label': 'Source IP',
        'description': 'Source IP address (supports CIDR, ranges, wildcards)',
        'category': 'source',
        'examples': ['192.168.1.1', '10.0.0.0/8', '192.168.1.1-192.168.1.50', '192.168.*.*'],
    },
    'srcport': {
        'label': 'Source Port',
        'description': 'Source port number or range',
        'category': 'source',
        'examples': ['443', '1024-65535', '80'],
    },
    'srcintf': {
        'label': 'Source Interface',
        'description': 'Source network interface',
        'category': 'source',
        'examples': ['port1', 'wan1', 'internal'],
    },
    'srczone': {
        'label': 'Source Zone',
        'description': 'Source security zone',
        'category': 'source',
        'examples': ['trust', 'untrust', 'dmz'],
    },
    'srcuser': {
        'label': 'Source User',
        'description': 'Source username',
        'category': 'source',
        'examples': ['admin', 'john.doe'],
    },
    'srccountry': {
        'label': 'Source Country',
        'description': 'Source country location',
        'category': 'source',
        'examples': ['United States', 'Germany', 'Reserved'],
    },
    # Destination fields
    'dstip': {
        'label': 'Destination IP',
        'description': 'Destination IP address (supports CIDR, ranges, wildcards)',
        'category': 'destination',
        'examples': ['8.8.8.8', '10.0.0.0/24', '192.168.1.1-192.168.1.100'],
    },
    'dstport': {
        'label': 'Destination Port',
        'description': 'Destination port number or range',
        'category': 'destination',
        'examples': ['443', '80', '22', '80-443'],
    },
    'dstintf': {
        'label': 'Destination Interface',
        'description': 'Destination network interface',
        'category': 'destination',
        'examples': ['port2', 'wan2', 'external'],
    },
    'dstzone': {
        'label': 'Destination Zone',
        'description': 'Destination security zone',
        'category': 'destination',
        'examples': ['trust', 'untrust', 'dmz'],
    },
    'dstuser': {
        'label': 'Destination User',
        'description': 'Destination username',
        'category': 'destination',
        'examples': [],
    },
    'dstcountry': {
        'label': 'Destination Country',
        'description': 'Destination country location',
        'category': 'destination',
        'examples': ['United States', 'Germany', 'Reserved'],
    },
    # Session fields
    'action': {
        'label': 'Action',
        'description': 'Firewall action (accept, deny, drop, close)',
        'category': 'session',
        'examples': ['accept', 'deny', 'drop', 'close', 'client-rst'],
    },
    'proto': {
        'label': 'Protocol',
        'description': 'IP protocol number or name',
        'category': 'session',
        'examples': ['6', '17', '1', 'TCP', 'UDP', 'ICMP'],
    },
    'service': {
        'label': 'Service',
        'description': 'Application service name',
        'category': 'session',
        'examples': ['HTTPS', 'HTTP', 'DNS', 'SSH', 'FTP'],
    },
    'app': {
        'label': 'Application',
        'description': 'Application name',
        'category': 'session',
        'examples': ['SSL', 'Facebook', 'YouTube', 'Google'],
    },
    'appcat': {
        'label': 'App Category',
        'description': 'Application category',
        'category': 'session',
        'examples': ['Social.Media', 'Video/Audio', 'Web.Client'],
    },
    # Policy fields
    'policyid': {
        'label': 'Policy ID',
        'description': 'Firewall policy ID',
        'category': 'policy',
        'examples': ['1', '100', '0'],
    },
    'policyname': {
        'label': 'Policy Name',
        'description': 'Firewall policy name',
        'category': 'policy',
        'examples': ['allow-internet', 'block-malware'],
    },
    'rule': {
        'label': 'Rule',
        'description': 'Firewall rule name (Palo Alto)',
        'category': 'policy',
        'examples': [],
    },
    # Device fields
    'device': {
        'label': 'Device IP',
        'description': 'Firewall device IP address',
        'category': 'device',
        'examples': ['192.168.100.1', '10.0.0.1'],
    },
    'device_name': {
        'label': 'Device Name',
        'description': 'Firewall device hostname',
        'category': 'device',
        'examples': ['FW-01', 'PA-500'],
    },
    # Log type fields
    'type': {
        'label': 'Log Type',
        'description': 'Type of log entry',
        'category': 'log',
        'examples': ['traffic', 'utm', 'event'],
    },
    'subtype': {
        'label': 'Log Subtype',
        'description': 'Subtype of log entry',
        'category': 'log',
        'examples': ['forward', 'local', 'start', 'end'],
    },
    'severity': {
        'label': 'Severity',
        'description': 'Log severity level (0-7)',
        'category': 'log',
        'examples': ['0', '3', '4', '6'],
    },
    # NAT fields
    'nat_srcip': {
        'label': 'NAT Source IP',
        'description': 'NAT translated source IP',
        'category': 'nat',
        'examples': ['203.0.113.1'],
    },
    'nat_dstip': {
        'label': 'NAT Destination IP',
        'description': 'NAT translated destination IP',
        'category': 'nat',
        'examples': ['10.0.0.100'],
    },
}


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
    include_raw: bool = Query(False, description="Include raw message and parsed_data (slower)"),
):
    """
    Search logs with advanced filtering.

    By default, excludes 'raw' and 'parsed_data' columns for faster queries.
    Set include_raw=true to include full log data when needed.
    """
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
            include_raw=include_raw,
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
    include_raw: bool = Query(False, description="Include raw message and parsed_data (slower)"),
):
    """
    Get most recent logs.

    By default, excludes 'raw' and 'parsed_data' columns for faster queries.
    """
    try:
        logs = ClickHouseClient.get_recent_logs(limit=limit, include_raw=include_raw)
        return [format_log_entry(log) for log in logs]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/detail")
async def get_log_detail(
    timestamp: str = Query(..., description="Log timestamp in ISO format"),
    device: str = Query(..., description="Device IP that logged the entry"),
):
    """
    Get full log details including raw message and parsed_data.

    Use this endpoint to fetch complete log data on demand (e.g., when user
    clicks "View Raw" on a log entry). This is more efficient than fetching
    raw data for all logs in a search.
    """
    try:
        log = ClickHouseClient.get_log_by_id(
            timestamp=timestamp,
            device_ip=device,
            include_raw=True
        )

        if not log:
            raise HTTPException(status_code=404, detail="Log entry not found")

        formatted = format_log_entry(log)

        # Format timestamp for JSON serialization
        if 'timestamp' in formatted and hasattr(formatted['timestamp'], 'isoformat'):
            formatted['timestamp'] = formatted['timestamp'].isoformat()

        return formatted
    except HTTPException:
        raise
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
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    try:
        # Run all 4 independent ClickHouse queries in parallel
        loop = asyncio.get_event_loop()
        _pool = ThreadPoolExecutor(max_workers=4)
        recent_future = loop.run_in_executor(_pool, lambda: ClickHouseClient.get_recent_logs(limit=50))
        severity_future = loop.run_in_executor(_pool, lambda: ClickHouseClient.get_severity_distribution(hours=24))
        traffic_future = loop.run_in_executor(_pool, lambda: ClickHouseClient.get_traffic_timeline(hours=1))
        totals_future = loop.run_in_executor(_pool, lambda: (ClickHouseClient.get_total_logs_24h(), ClickHouseClient.get_unique_devices_count()))

        recent_logs, severity_dist, traffic, totals = await asyncio.gather(
            recent_future, severity_future, traffic_future, totals_future
        )
        total_logs_24h, unique_devices = totals

        severity_counts = {}
        for row in severity_dist:
            sev = row.get('severity', 6)
            severity_counts[SEVERITY_NAMES.get(sev, 'Unknown')] = row.get('count', 0)

        traffic_timeline = [
            {
                'time': row['minute'].isoformat() if hasattr(row['minute'], 'isoformat') else str(row['minute']),
                'count': row['count']
            }
            for row in traffic
        ]

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


@router.get("/search-fields")
async def get_search_fields():
    """
    Get all available search fields for autocomplete.

    Returns field definitions organized by category with labels,
    descriptions, and example values.
    """
    # Group fields by category
    categories = {}
    for field, info in SEARCH_FIELDS.items():
        cat = info['category']
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            'field': field,
            **info
        })

    # Define category order and labels
    category_order = [
        ('source', 'Source'),
        ('destination', 'Destination'),
        ('session', 'Session'),
        ('policy', 'Policy'),
        ('device', 'Device'),
        ('log', 'Log Type'),
        ('nat', 'NAT'),
    ]

    return {
        'fields': SEARCH_FIELDS,
        'categories': categories,
        'category_order': category_order,
        'syntax_help': {
            'basic': 'field:value (e.g., srcip:192.168.1.1)',
            'negation': '-field:value (e.g., -action:deny)',
            'cidr': 'srcip:192.168.0.0/24 or dstip:10.0.0.0/8',
            'range': 'srcip:192.168.1.1-192.168.1.50 or dstport:80-443',
            'wildcard': 'srcip:192.168.*.* or dstip:10.*.*.*',
            'text': 'keyword or "phrase with spaces"',
            'combine': 'srcip:10.0.0.1 dstport:443 action:accept',
        }
    }


@router.get("/search-suggest")
async def get_search_suggestions(
    q: str = Query("", description="Current search query or partial input"),
    field: Optional[str] = Query(None, description="Specific field to get values for"),
):
    """
    Get search suggestions based on current input.

    - If input is empty or a partial field name, returns matching field names
    - If input is a complete field with colon (e.g., "action:"), returns common values for that field
    - If field parameter is provided, returns recent unique values for that field from the database
    """
    suggestions = []

    # If a specific field is requested, get values from database
    if field and field in SEARCH_FIELDS:
        try:
            values = ClickHouseClient.get_field_values(field, limit=20)
            return {
                'type': 'values',
                'field': field,
                'field_info': SEARCH_FIELDS[field],
                'values': values,
            }
        except Exception:
            # Fall back to examples if database query fails
            return {
                'type': 'values',
                'field': field,
                'field_info': SEARCH_FIELDS[field],
                'values': SEARCH_FIELDS[field].get('examples', []),
            }

    # Parse current query to understand context
    q = q.strip()

    # If empty or just started typing, suggest all fields
    if not q:
        for field_name, info in SEARCH_FIELDS.items():
            suggestions.append({
                'type': 'field',
                'value': f'{field_name}:',
                'label': info['label'],
                'description': info['description'],
                'category': info['category'],
            })
        return {'type': 'fields', 'suggestions': suggestions}

    # Check if we're typing a field name (no colon yet)
    if ':' not in q.split()[-1]:
        # Get the last word being typed
        parts = q.rsplit(None, 1)
        prefix = parts[-1].lower() if parts else q.lower()

        # Handle negation prefix
        is_negated = prefix.startswith('-')
        if is_negated:
            prefix = prefix[1:]

        neg_prefix = '-' if is_negated else ''

        # Find matching fields
        for field_name, info in SEARCH_FIELDS.items():
            if field_name.startswith(prefix) or info['label'].lower().startswith(prefix):
                suggestions.append({
                    'type': 'field',
                    'value': f'{neg_prefix}{field_name}:',
                    'label': info['label'],
                    'description': info['description'],
                    'category': info['category'],
                })

        return {'type': 'fields', 'suggestions': suggestions[:15]}

    # We have a colon, so we're typing a value
    last_part = q.split()[-1]
    if ':' in last_part:
        field_part, value_part = last_part.split(':', 1)
        field_name = field_part.lstrip('-')

        if field_name in SEARCH_FIELDS:
            field_info = SEARCH_FIELDS[field_name]

            # Try to get values from database
            try:
                db_values = ClickHouseClient.get_field_values(field_name, limit=20)
                if value_part:
                    # Filter by prefix
                    db_values = [v for v in db_values if str(v).lower().startswith(value_part.lower())]

                for val in db_values[:10]:
                    suggestions.append({
                        'type': 'value',
                        'value': str(val),
                        'field': field_name,
                    })
            except Exception:
                pass

            # Add examples if we don't have enough suggestions
            if len(suggestions) < 5:
                for example in field_info.get('examples', []):
                    if not value_part or example.lower().startswith(value_part.lower()):
                        if not any(s['value'] == example for s in suggestions):
                            suggestions.append({
                                'type': 'example',
                                'value': example,
                                'field': field_name,
                            })

            return {
                'type': 'values',
                'field': field_name,
                'field_info': field_info,
                'suggestions': suggestions[:15],
            }

    return {'type': 'none', 'suggestions': []}
