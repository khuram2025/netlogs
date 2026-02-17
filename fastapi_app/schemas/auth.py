"""
Pydantic schemas for request validation on security-critical API endpoints.
"""

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================
# Enums
# ============================================================

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class APIKeyPermission(str, Enum):
    read = "read"
    write = "write"
    admin = "admin"


# ============================================================
# User schemas
# ============================================================

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    email: Optional[str] = Field(None, max_length=255)
    role: UserRole = UserRole.VIEWER

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Must contain at least one digit")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if v and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
                raise ValueError("Invalid email format")
            if not v:
                return None
        return v


class UpdateUserRequest(BaseModel):
    email: Optional[str] = Field(None, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if v and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
                raise ValueError("Invalid email format")
            if not v:
                return None
        return v


class ResetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Must contain at least one digit")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Must contain at least one digit")
        return v


# ============================================================
# API Key schemas
# ============================================================

class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    permissions: list[APIKeyPermission] = [APIKeyPermission.read]
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)


class UpdateAPIKeyRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    permissions: Optional[list[APIKeyPermission]] = None


# ============================================================
# Alert schemas
# ============================================================

class AlertRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    rule_type: str = Field(..., pattern=r"^(threshold|pattern|absence|anomaly)$")
    severity: str = Field(..., pattern=r"^(critical|high|medium|low|info)$")
    conditions: dict = Field(default_factory=dict)
    is_enabled: bool = True
    notification_channel_ids: list[int] = Field(default_factory=list)


class NotificationChannelRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    channel_type: str = Field(..., pattern=r"^(email|telegram|webhook)$")
    config: dict = Field(default_factory=dict)
    is_enabled: bool = True


# ============================================================
# Setup wizard schemas
# ============================================================

class SetupStep1Request(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
    email: Optional[str] = Field(None, max_length=255)

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Must contain at least one digit")
        if v == "changeme":
            raise ValueError("Please choose a different password")
        return v


class SetupStep2Request(BaseModel):
    channel_type: str = Field(..., pattern=r"^(email|telegram|webhook)$")
    name: str = Field(..., min_length=1, max_length=200)
    config: dict = Field(default_factory=dict)
    test: bool = False
