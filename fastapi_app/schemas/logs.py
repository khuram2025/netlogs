"""
Pydantic schemas for Log operations.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    """Schema for a single log entry from ClickHouse."""
    timestamp: datetime
    device_ip: str
    facility: int
    severity: int
    message: str
    raw: str = ""
    parsed_data: Dict[str, str] = Field(default_factory=dict)

    # Materialized columns
    log_date: Optional[str] = None
    log_hour: Optional[int] = None
    action: Optional[str] = None
    srcip: Optional[str] = None
    dstip: Optional[str] = None


class LogSearchParams(BaseModel):
    """Parameters for log search."""
    device: Optional[str] = None
    severity: Optional[int] = None
    facility: Optional[int] = None
    q: Optional[str] = None  # Search query
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class LogSearchResponse(BaseModel):
    """Response for log search."""
    logs: List[LogEntry]
    total: int
    limit: int
    offset: int
    has_more: bool


class LogStats(BaseModel):
    """Log statistics."""
    total_logs: int = 0
    severity_distribution: Dict[int, int] = Field(default_factory=dict)
    device_distribution: Dict[str, int] = Field(default_factory=dict)
    action_distribution: Dict[str, int] = Field(default_factory=dict)


class DashboardStats(BaseModel):
    """Dashboard statistics."""
    recent_logs: List[LogEntry]
    severity_counts: Dict[str, int]
    traffic_timeline: List[Dict[str, Any]]
    total_logs_24h: int
    unique_devices: int


class StorageStats(BaseModel):
    """Storage statistics."""
    total_rows: int
    total_bytes: int
    compressed_bytes: int
    total_display: str
    compressed_display: str
    compression_ratio: float


class PerDeviceStorage(BaseModel):
    """Per-device storage stats."""
    device_ip: str
    log_count: int
    storage_bytes: int
    oldest_log: Optional[datetime] = None
    newest_log: Optional[datetime] = None
