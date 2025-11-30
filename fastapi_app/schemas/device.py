"""
Pydantic schemas for Device model.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, List, Union, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator


class DeviceBase(BaseModel):
    """Base schema for Device."""
    ip_address: str
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    parser: str = "GENERIC"
    retention_days: int = 90

    @field_validator('ip_address', mode='before')
    @classmethod
    def convert_ip_to_string(cls, v: Any) -> str:
        """Convert IPv4Address/IPv6Address objects to string."""
        if isinstance(v, (IPv4Address, IPv6Address)):
            return str(v)
        return v


class DeviceCreate(DeviceBase):
    """Schema for creating a device."""
    pass


class DeviceUpdate(BaseModel):
    """Schema for updating a device."""
    hostname: Optional[str] = None
    parser: Optional[str] = None
    retention_days: Optional[int] = None
    device_type: Optional[str] = None


class DeviceResponse(DeviceBase):
    """Schema for device response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    created_at: datetime
    updated_at: datetime
    last_log_received: Optional[datetime] = None
    log_count: int = 0

    # Computed fields
    status_display: str = ""
    parser_display: str = ""
    retention_display: str = ""
    is_stale: bool = False


class DeviceWithStorage(DeviceResponse):
    """Device with storage statistics from ClickHouse."""
    storage_bytes: int = 0
    storage_display: str = "0 B"
    log_count_display: str = "0"


class DeviceListResponse(BaseModel):
    """Response for device list with totals."""
    devices: List[DeviceWithStorage]
    total_count: int
    total_storage: int
    total_storage_display: str
    total_logs: int


class DeviceStatusUpdate(BaseModel):
    """Schema for status update."""
    status: str = Field(..., pattern="^(APPROVED|REJECTED|PENDING)$")
