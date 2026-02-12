"""
Role-Based Access Control (RBAC) permission system.

Permission hierarchy: ADMIN > ANALYST > VIEWER
"""

import functools
import logging
from typing import List, Optional

from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)

# Role hierarchy (higher index = more privileges)
ROLE_HIERARCHY = {
    "VIEWER": 0,
    "ANALYST": 1,
    "ADMIN": 2,
}


def _get_user(request: Request):
    """Extract current user from request state."""
    return getattr(request.state, "current_user", None)


def require_role(*allowed_roles: str):
    """FastAPI dependency that checks if the current user has one of the allowed roles.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role("ADMIN"))])
        async def admin_page(request: Request): ...

    Or as a callable dependency:
        async def my_route(request: Request, _=Depends(require_role("ADMIN", "ANALYST"))): ...
    """
    async def _check_role(request: Request):
        user = _get_user(request)
        if user is None:
            if request.url.path.startswith("/api/"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
            from fastapi.responses import RedirectResponse
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": f"/auth/login?next={request.url.path}"},
            )

        if user.role not in allowed_roles:
            if request.url.path.startswith("/api/"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}",
                )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this page.",
            )

        return user

    return _check_role


def require_min_role(min_role: str):
    """FastAPI dependency that requires at least the given role level.

    Uses role hierarchy: VIEWER < ANALYST < ADMIN

    Usage:
        @router.get("/analyst-up", dependencies=[Depends(require_min_role("ANALYST"))])
    """
    min_level = ROLE_HIERARCHY.get(min_role, 0)

    async def _check_min_role(request: Request):
        user = _get_user(request)
        if user is None:
            if request.url.path.startswith("/api/"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": f"/auth/login?next={request.url.path}"},
            )

        user_level = ROLE_HIERARCHY.get(user.role, 0)
        if user_level < min_level:
            if request.url.path.startswith("/api/"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Minimum role required: {min_role}",
                )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this page.",
            )

        return user

    return _check_min_role


def can_access(user, feature: str) -> bool:
    """Check if a user can access a specific feature.
    Used in templates for conditional rendering.

    Permission Matrix:
    | Feature              | ADMIN | ANALYST | VIEWER |
    |---------------------|-------|---------|--------|
    | Dashboard           | Full  | Full    | Full   |
    | Log Viewer          | Full  | Full    | Read   |
    | Log Search          | Full  | Full    | Full   |
    | Policy Builder      | Full  | Full    | Read   |
    | Device Management   | Full  | View+   | View   |
    | Device SSH/Creds    | Full  | No      | No     |
    | EDL Management      | Full  | Full    | View   |
    | Projects            | Full  | Full    | View   |
    | System Monitor      | Full  | View    | No     |
    | Storage Settings    | Full  | No      | No     |
    | User Management     | Full  | No      | No     |
    | Alert Rules         | Full  | Full    | View   |
    | Incidents           | Full  | Full    | View   |
    | API Keys            | Full  | Own     | No     |
    """
    if user is None:
        return False

    role = user.role

    PERMISSIONS = {
        "dashboard": ["ADMIN", "ANALYST", "VIEWER"],
        "log_viewer": ["ADMIN", "ANALYST", "VIEWER"],
        "log_search": ["ADMIN", "ANALYST", "VIEWER"],
        "policy_builder": ["ADMIN", "ANALYST", "VIEWER"],
        "device_management": ["ADMIN", "ANALYST", "VIEWER"],
        "device_edit": ["ADMIN"],
        "device_approve": ["ADMIN", "ANALYST"],
        "device_credentials": ["ADMIN"],
        "edl_management": ["ADMIN", "ANALYST", "VIEWER"],
        "edl_edit": ["ADMIN", "ANALYST"],
        "projects": ["ADMIN", "ANALYST", "VIEWER"],
        "project_edit": ["ADMIN", "ANALYST"],
        "system_monitor": ["ADMIN", "ANALYST"],
        "storage_settings": ["ADMIN"],
        "user_management": ["ADMIN"],
        "alert_rules": ["ADMIN", "ANALYST", "VIEWER"],
        "alert_rules_edit": ["ADMIN", "ANALYST"],
        "incidents": ["ADMIN", "ANALYST", "VIEWER"],
        "incidents_manage": ["ADMIN", "ANALYST"],
        "api_keys": ["ADMIN", "ANALYST"],
    }

    allowed = PERMISSIONS.get(feature, [])
    return role in allowed
