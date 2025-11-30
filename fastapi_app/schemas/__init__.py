# Pydantic schemas for request/response validation
from .device import (
    DeviceBase,
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DeviceWithStorage,
    DeviceListResponse,
    DeviceStatusUpdate,
)
from .logs import (
    LogEntry,
    LogSearchParams,
    LogSearchResponse,
    LogStats,
    DashboardStats,
    StorageStats,
    PerDeviceStorage,
)

__all__ = [
    "DeviceBase",
    "DeviceCreate",
    "DeviceUpdate",
    "DeviceResponse",
    "DeviceWithStorage",
    "DeviceListResponse",
    "DeviceStatusUpdate",
    "LogEntry",
    "LogSearchParams",
    "LogSearchResponse",
    "LogStats",
    "DashboardStats",
    "StorageStats",
    "PerDeviceStorage",
]
