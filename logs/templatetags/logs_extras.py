from django import template
from django.contrib.humanize.templatetags.humanize import intcomma as humanize_intcomma

register = template.Library()

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


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def get_severity_name(value):
    try:
        return SEVERITY_MAP.get(int(value), str(value))
    except (ValueError, TypeError):
        return value


@register.filter
def get_facility_name(value):
    """Convert facility number to name."""
    try:
        return FACILITY_MAP.get(int(value), str(value))
    except (ValueError, TypeError):
        return str(value)


@register.filter
def split_pairs(value):
    """
    Split a string of 'key:value,key:value' pairs into a list of tuples.
    Usage: "15m:15m,1h:1 Hour"|split_pairs
    Returns: [('15m', '15m'), ('1h', '1 Hour'), ...]
    """
    result = []
    for pair in value.split(','):
        if ':' in pair:
            key, val = pair.split(':', 1)
            result.append((key.strip(), val.strip()))
    return result


@register.filter
def split_list(value):
    """
    Split a comma-separated string into a list.
    Usage: "25,50,100,200"|split_list
    Returns: ['25', '50', '100', '200']
    """
    return [item.strip() for item in value.split(',')]


@register.simple_tag(takes_context=True)
def query_string(context, **kwargs):
    """
    Build a query string from current GET parameters, with optional overrides.
    Usage: {% query_string page=2 %}
    Returns: page=2&q=search&... (preserving other params)
    """
    request = context.get('request')
    if request is None:
        params = {}
    else:
        params = request.GET.copy()

    for key, value in kwargs.items():
        params[key] = value

    return params.urlencode()


@register.filter
def intcomma(value):
    """Format a number with commas as thousands separators."""
    try:
        return humanize_intcomma(value)
    except (ValueError, TypeError):
        return value


# Protocol number to name mapping
PROTOCOL_MAP = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '58': 'ICMPv6',
    '89': 'OSPF',
    '132': 'SCTP',
}


@register.filter
def proto_name(value):
    """Convert protocol number to name."""
    if value is None:
        return '-'
    str_val = str(value)
    return PROTOCOL_MAP.get(str_val, str_val)


@register.filter
def format_bytes(value):
    """Format bytes into human readable format."""
    if value is None or value == '':
        return '0'
    try:
        num = int(value)
        if num < 1024:
            return f'{num}B'
        elif num < 1024 * 1024:
            return f'{num / 1024:.1f}K'
        elif num < 1024 * 1024 * 1024:
            return f'{num / (1024 * 1024):.1f}M'
        else:
            return f'{num / (1024 * 1024 * 1024):.1f}G'
    except (ValueError, TypeError):
        return str(value)


@register.filter
def dict_get(dictionary, key):
    """
    Get a value from a dictionary by key.
    Usage: {{ my_dict|dict_get:key_var }}
    Returns None if key not found or dictionary is not a dict.
    """
    if not isinstance(dictionary, dict):
        return None
    return dictionary.get(key)
