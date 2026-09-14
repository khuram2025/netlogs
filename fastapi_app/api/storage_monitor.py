"""Read host storage through the restricted local management socket; never container capacity."""
import threading
import time
import httpx
import math

_lock = threading.Lock()
_cached = None
_expires = 0


def snapshot():
    global _cached, _expires
    with _lock:
        if _cached is not None and time.monotonic() < _expires:
            return _cached
        with httpx.Client(transport=httpx.HTTPTransport(uds='/run/zenshield/agent.sock'), timeout=15) as client:
            response = client.post('http://localhost/rpc', json={'operation': 'storage.metrics', 'body': {}})
            response.raise_for_status()
            data = response.json()
        _cached, _expires = data, time.monotonic() + 5
        return data


def get_disk_usage(path='/'):
    data = snapshot()
    fs = data.get('data_filesystem')
    if not fs:
        raise RuntimeError(data.get('data_error') or 'Host data filesystem is unavailable')
    total, used, free = fs['size'], fs['used'], fs['available']
    return {'total_bytes': total, 'used_bytes': used, 'free_bytes': free,
            'total_gb': round(total / 1024**3, 1), 'used_gb': round(used / 1024**3, 1),
            'free_gb': round(free / 1024**3, 1), 'usage_percent': fs['usage_percent'],
            'mount': fs['mount'], 'source': fs['source'], 'scope': 'ClickHouse data filesystem'}


def fmt(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}'
        value /= 1024


def get_system_partitions():
    data = snapshot()
    disks = [{'name': d['path'].removeprefix('/dev/'), 'size': d['size'], 'size_readable': fmt(d['size']),
              'model': d['model'], 'vendor': '', 'fstype': d['fstype'], 'has_partitions': d['children_count'] > 0,
              'children_count': d['children_count'], 'is_lvm_member': d['fstype'] == 'LVM2_member'} for d in data['disks']]
    partitions = [{'name': fs['source'].removeprefix('/dev/'), 'type': 'lvm' if '/mapper/' in fs['source'] else 'part',
                   'mountpoint': fs['mount'], 'fstype': fs['fstype'], 'size': fs['size'], 'size_readable': fmt(fs['size']),
                   'used': fs['used'], 'used_readable': fmt(fs['used']), 'available': fs['available'],
                   'available_readable': fmt(fs['available']), 'usage_percent': fs['usage_percent'],
                   'usage_pct_str': str(fs['usage_percent']) + '%', 'model': '', 'vendor': ''} for fs in data['filesystems']]
    return {'disks': disks, 'partitions': partitions, 'has_hostfs': True,
            'unallocated': [{**d, 'status': 'Available blank disk'} for d, raw in zip(disks, data['disks']) if raw['blank']]}


def validate_settings(body, current):
    if not isinstance(body, dict):
        raise ValueError('Storage settings must be a JSON object')
    defaults = {'syslogs_max_size_gb': 600, 'cleanup_trigger_percent': 95, 'cleanup_target_percent': 80,
                'disk_warning_percent': 85, 'disk_critical_percent': 95, 'min_retention_days': 7,
                'monitor_interval_minutes': 5}
    values = {}
    for name, default in defaults.items():
        value = body.get(name, getattr(current, name, None) or default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(name + ' must be a positive finite number')
        if name.endswith('_percent') and value > 100:
            raise ValueError(name + ' cannot exceed 100')
        if name in {'min_retention_days', 'monitor_interval_minutes'} and value != int(value):
            raise ValueError(name + ' must be a whole number')
        values[name] = value
    if values['cleanup_target_percent'] >= values['cleanup_trigger_percent']:
        raise ValueError('Cleanup target must be below its trigger percentage')
    if values['disk_warning_percent'] >= values['disk_critical_percent']:
        raise ValueError('Disk warning must be below the critical percentage')
    if 'auto_cleanup_enabled' in body and type(body['auto_cleanup_enabled']) is not bool:
        raise ValueError('Auto cleanup must be true or false')
