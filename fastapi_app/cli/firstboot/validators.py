"""Input validators for the first-boot wizard."""

import ipaddress
import re
import os


def validate_ip(value: str) -> str | None:
    """Validate an IPv4 address. Returns error message or None."""
    try:
        ipaddress.IPv4Address(value)
        return None
    except (ipaddress.AddressValueError, ValueError):
        return "Invalid IPv4 address"


def validate_cidr(value: str) -> str | None:
    """Validate IP/CIDR notation (e.g., 192.168.1.10/24). Returns error or None."""
    if "/" not in value:
        return "Must include CIDR prefix (e.g., 192.168.1.10/24)"
    try:
        ipaddress.IPv4Interface(value)
        return None
    except (ipaddress.AddressValueError, ValueError) as e:
        return f"Invalid CIDR: {e}"


def validate_gateway(value: str) -> str | None:
    """Validate a gateway IP address."""
    return validate_ip(value)


def validate_dns(value: str) -> str | None:
    """Validate DNS server (IP address)."""
    return validate_ip(value)


def validate_hostname(value: str) -> str | None:
    """Validate hostname. Returns error message or None."""
    if not value:
        return "Hostname cannot be empty"
    if len(value) > 63:
        return "Hostname must be 63 characters or less"
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9-]*$', value):
        return "Hostname must start with a letter and contain only letters, digits, and hyphens"
    return None


def validate_timezone(value: str) -> str | None:
    """Validate timezone string. Returns error message or None."""
    if not value:
        return "Timezone cannot be empty"
    # Check against system timezone database
    tz_path = f"/usr/share/zoneinfo/{value}"
    if os.path.isfile(tz_path):
        return None
    # Common aliases
    if value.upper() == "UTC":
        return None
    return f"Unknown timezone: {value} (e.g., America/New_York, UTC, Europe/London)"


def validate_password(value: str) -> str | None:
    """Validate password strength. Returns error message or None."""
    if len(value) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', value):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', value):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', value):
        return "Password must contain at least one digit"
    return None


def validate_ntp(value: str) -> str | None:
    """Validate NTP server (hostname or IP)."""
    if not value:
        return "NTP server cannot be empty"
    # Allow hostnames and IPs
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]+$', value):
        return None
    return "Invalid NTP server address"


def validate_email(value: str) -> str | None:
    """Validate email address (optional — empty is OK)."""
    if not value:
        return None  # Email is optional
    if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
        return None
    return "Invalid email address"
