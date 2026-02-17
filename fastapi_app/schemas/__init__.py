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

from .auth import (
    CreateUserRequest,
    UpdateUserRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    CreateAPIKeyRequest,
    UpdateAPIKeyRequest,
    AlertRuleRequest,
    NotificationChannelRequest,
    SetupStep1Request,
    SetupStep2Request,
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
    "CreateUserRequest",
    "UpdateUserRequest",
    "ResetPasswordRequest",
    "ChangePasswordRequest",
    "CreateAPIKeyRequest",
    "UpdateAPIKeyRequest",
    "AlertRuleRequest",
    "NotificationChannelRequest",
    "SetupStep1Request",
    "SetupStep2Request",
]
