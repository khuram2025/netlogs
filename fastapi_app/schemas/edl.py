"""Pydantic schemas for External Dynamic List (EDL) validation."""
import re
import ipaddress
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class EDLType(str, Enum):
    """Type of entries allowed in the list."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


# --- EDL List Schemas ---

class EDLListBase(BaseModel):
    """Base schema for EDL list."""
    name: str = Field(..., min_length=1, max_length=255, description="Unique name for the list")
    description: Optional[str] = Field(None, max_length=1000)
    list_type: EDLType = Field(default=EDLType.IP, description="Type of entries in this list")
    is_active: bool = Field(default=True)

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Validate list name - alphanumeric, hyphens, underscores only."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v.replace(' ', '_')):
            raise ValueError('Name must contain only letters, numbers, spaces, hyphens, and underscores')
        return v.strip()


class EDLListCreate(EDLListBase):
    """Schema for creating a new EDL list."""
    access_token: Optional[str] = Field(None, max_length=64, description="Optional access token for protected lists")


class EDLListUpdate(BaseModel):
    """Schema for updating an EDL list."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    is_active: Optional[bool] = None
    access_token: Optional[str] = Field(None, max_length=64)

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is not None:
            if not re.match(r'^[a-zA-Z0-9_\- ]+$', v):
                raise ValueError('Name must contain only letters, numbers, spaces, hyphens, and underscores')
            return v.strip()
        return v


class EDLListResponse(EDLListBase):
    """Response schema for EDL list."""
    id: int
    access_token: Optional[str] = None
    entry_count: int = 0
    active_entry_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# --- EDL Entry Schemas ---

class EDLEntryBase(BaseModel):
    """Base schema for EDL entry."""
    value: str = Field(..., min_length=1, max_length=2048, description="IP address, domain, or URL")
    description: Optional[str] = Field(None, max_length=500)
    is_active: bool = Field(default=True)
    expires_at: Optional[datetime] = Field(None, description="Optional expiration date")


class EDLEntryCreate(EDLEntryBase):
    """Schema for creating a new EDL entry."""
    source: str = Field(default="manual", max_length=100)

    @field_validator('value')
    @classmethod
    def validate_value(cls, v):
        """Basic validation - detailed validation happens based on list type."""
        return v.strip()


class EDLEntryUpdate(BaseModel):
    """Schema for updating an EDL entry."""
    value: Optional[str] = Field(None, min_length=1, max_length=2048)
    description: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None
    expires_at: Optional[datetime] = None

    @field_validator('value')
    @classmethod
    def validate_value(cls, v):
        if v is not None:
            return v.strip()
        return v


class EDLEntryResponse(EDLEntryBase):
    """Response schema for EDL entry."""
    id: int
    edl_list_id: int
    source: Optional[str] = None
    is_expired: bool = False
    is_effective: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# --- Bulk Import/Export Schemas ---

class BulkImportRequest(BaseModel):
    """Schema for bulk import request."""
    entries: List[str] = Field(..., description="List of values to import")
    description: Optional[str] = Field(None, description="Default description for all entries")
    overwrite: bool = Field(default=False, description="If true, replaces all existing entries")


class BulkImportResult(BaseModel):
    """Result of bulk import operation."""
    total: int = Field(description="Total entries in request")
    imported: int = Field(description="Successfully imported entries")
    skipped: int = Field(description="Skipped entries (duplicates or invalid)")
    errors: List[str] = Field(default_factory=list, description="Error messages for failed entries")


class ExportFormat(str, Enum):
    """Export format options."""
    TXT = "txt"
    CSV = "csv"
    JSON = "json"


# --- Validation Helpers ---

def validate_ip_entry(value: str) -> tuple[bool, str]:
    """Validate IP address entry (IPv4, IPv6, CIDR notation)."""
    value = value.strip()

    # Skip comments
    if value.startswith('#') or not value:
        return False, "Empty or comment line"

    try:
        # Try as single IP
        ipaddress.ip_address(value)
        return True, ""
    except ValueError:
        pass

    try:
        # Try as network (CIDR)
        ipaddress.ip_network(value, strict=False)
        return True, ""
    except ValueError:
        pass

    # Try as IP range (e.g., 192.168.1.1-192.168.1.10)
    if '-' in value and not value.startswith('-'):
        parts = value.split('-')
        if len(parts) == 2:
            try:
                ipaddress.ip_address(parts[0].strip())
                ipaddress.ip_address(parts[1].strip())
                return True, ""
            except ValueError:
                pass

    return False, f"Invalid IP address format: {value}"


def validate_domain_entry(value: str) -> tuple[bool, str]:
    """Validate domain entry."""
    value = value.strip().lower()

    # Skip comments
    if value.startswith('#') or not value:
        return False, "Empty or comment line"

    # Remove leading wildcard for validation
    if value.startswith('*.'):
        value = value[2:]

    # Basic domain validation
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, value):
        return True, ""

    # Single-label domain (internal)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$', value):
        return True, ""

    return False, f"Invalid domain format: {value}"


def validate_url_entry(value: str) -> tuple[bool, str]:
    """Validate URL entry."""
    value = value.strip()

    # Skip comments
    if value.startswith('#') or not value:
        return False, "Empty or comment line"

    # Basic URL pattern
    url_pattern = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    if re.match(url_pattern, value):
        return True, ""

    # URL path pattern (without scheme)
    path_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+(/[^\s<>"{}|\\^`\[\]]*)?$'
    if re.match(path_pattern, value):
        return True, ""

    return False, f"Invalid URL format: {value}"


def validate_entry_for_type(value: str, list_type: EDLType) -> tuple[bool, str]:
    """Validate entry value based on list type."""
    validators = {
        EDLType.IP: validate_ip_entry,
        EDLType.DOMAIN: validate_domain_entry,
        EDLType.URL: validate_url_entry,
    }
    return validators.get(list_type, lambda v: (True, ""))(value)
