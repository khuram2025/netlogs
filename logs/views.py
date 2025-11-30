from django.shortcuts import render
from django.http import JsonResponse
from .clickhouse_client import ClickHouseClient
import math

SEVERITY_MAP = {
    0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error', 4: 'Warning',
    5: 'Notice', 6: 'Info', 7: 'Debug'
}

FACILITY_MAP = {
    0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon', 4: 'auth', 5: 'syslog',
    6: 'lpr', 7: 'news', 8: 'uucp', 9: 'cron', 10: 'authpriv', 11: 'ftp',
    16: 'local0', 17: 'local1', 18: 'local2', 19: 'local3', 20: 'local4',
    21: 'local5', 22: 'local6', 23: 'local7'
}


def dashboard(request):
    try:
        logs = ClickHouseClient.get_recent_logs(limit=50)
        stats = ClickHouseClient.get_stats()

        # Process stats for display
        severity_data = []
        for item in stats['severity']:
            severity_data.append({
                'name': SEVERITY_MAP.get(item['severity'], str(item['severity'])),
                'count': item['count']
            })

        timeline_labels = [item['t'].strftime('%H:%M') for item in stats['traffic']]
        timeline_data = [item['count'] for item in stats['traffic']]

        context = {
            'logs': logs,
            'severity_data': severity_data,
            'timeline_labels': timeline_labels,
            'timeline_data': timeline_data,
            'severity_map': SEVERITY_MAP,
        }
    except Exception as e:
        context = {'error': str(e)}

    return render(request, 'logs/dashboard.html', context)


def log_list(request):
    """Enterprise log viewer with advanced filtering and pagination."""

    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))
    per_page = min(per_page, 200)  # Max 200 per page

    # Filters
    device_ips = request.GET.getlist('device')
    # Filter out empty strings from device list
    device_ips = [d for d in device_ips if d]
    severities = request.GET.getlist('severity')
    facilities = request.GET.getlist('facility')
    query_text = request.GET.get('q', '').strip()
    start_time = request.GET.get('start')
    end_time = request.GET.get('end')
    time_range = request.GET.get('time_range', '15m')  # Quick time range selector

    # Normalize datetime format from HTML datetime-local input (2025-11-27T08:00)
    # to ClickHouse format (2025-11-27 08:00:00)
    def normalize_datetime(dt_str):
        if not dt_str:
            return None
        # Replace T with space and add seconds if missing
        dt_str = dt_str.replace('T', ' ')
        if len(dt_str) == 16:  # YYYY-MM-DD HH:MM
            dt_str += ':00'
        return dt_str

    start_time = normalize_datetime(start_time)
    end_time = normalize_datetime(end_time)

    # Convert to int lists
    if severities:
        severities = [int(s) for s in severities if s.isdigit()]
    if facilities:
        facilities = [int(f) for f in facilities if f.isdigit()]

    # Handle quick time range
    if time_range and not start_time:
        from datetime import datetime, timedelta, timezone
        # Use UTC time since ClickHouse stores timestamps in UTC
        now = datetime.now(timezone.utc)
        ranges = {
            '15m': timedelta(minutes=15),
            '1h': timedelta(hours=1),
            '6h': timedelta(hours=6),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
        }
        if time_range in ranges:
            start_time = (now - ranges[time_range]).strftime('%Y-%m-%d %H:%M:%S')

    # Calculate offset
    offset = (page - 1) * per_page

    # Get total count for pagination
    total_count = ClickHouseClient.count_logs(
        device_ips=device_ips or None,
        severities=severities or None,
        facilities=facilities or None,
        start_time=start_time,
        end_time=end_time,
        query_text=query_text or None
    )

    # Fetch logs
    logs = ClickHouseClient.search_logs(
        limit=per_page,
        offset=offset,
        device_ips=device_ips or None,
        severities=severities or None,
        facilities=facilities or None,
        start_time=start_time,
        end_time=end_time,
        query_text=query_text or None
    )

    # Get summary stats based on current filters
    try:
        stats_summary = ClickHouseClient.get_log_stats_summary(
            device_ips=device_ips or None,
            start_time=start_time,
            end_time=end_time,
            query_text=query_text or None
        )
    except:
        stats_summary = {}

    # Fetch distinct devices for filter
    devices = ClickHouseClient.get_distinct_devices()

    # Calculate pagination
    total_pages = math.ceil(total_count / per_page) if total_count > 0 else 1
    has_prev = page > 1
    has_next = page < total_pages

    # Generate page numbers for pagination UI
    page_numbers = []
    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 4:
            page_numbers = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_numbers = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_numbers = [1, '...', page - 1, page, page + 1, '...', total_pages]

    context = {
        'logs': logs,
        'devices': devices,
        'selected_devices': device_ips,
        'selected_severities': severities,
        'selected_facilities': facilities,
        'query_text': query_text,
        'start_time': start_time,
        'end_time': end_time,
        'time_range': time_range,
        # Pagination
        'page': page,
        'per_page': per_page,
        'total_count': total_count,
        'total_pages': total_pages,
        'has_prev': has_prev,
        'has_next': has_next,
        'page_numbers': page_numbers,
        'showing_start': offset + 1 if total_count > 0 else 0,
        'showing_end': min(offset + per_page, total_count),
        # Stats
        'stats_summary': stats_summary,
        # Maps for display
        'severity_map': SEVERITY_MAP,
        'facility_map': FACILITY_MAP,
    }
    return render(request, 'logs/log_list.html', context)


def api_logs(request):
    """API endpoint for AJAX log fetching."""
    device_ips = request.GET.getlist('device')
    severities = request.GET.getlist('severity')
    query_text = request.GET.get('q', '').strip()
    start_time = request.GET.get('start')
    end_time = request.GET.get('end')
    limit = int(request.GET.get('limit', 50))
    offset = int(request.GET.get('offset', 0))

    if severities:
        severities = [int(s) for s in severities if s.isdigit()]

    logs = ClickHouseClient.search_logs(
        limit=limit,
        offset=offset,
        device_ips=device_ips or None,
        severities=severities or None,
        start_time=start_time,
        end_time=end_time,
        query_text=query_text or None
    )

    # Convert to JSON-serializable format
    result = []
    for log in logs:
        result.append({
            'timestamp': log['timestamp'].isoformat() if log.get('timestamp') else None,
            'device_ip': str(log.get('device_ip', '')),
            'facility': log.get('facility'),
            'severity': log.get('severity'),
            'message': log.get('message', ''),
            'raw': log.get('raw', ''),
            'parsed_data': dict(log.get('parsed_data', {}))
        })

    return JsonResponse({'logs': result, 'count': len(result)})
