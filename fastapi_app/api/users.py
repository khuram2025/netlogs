"""
User management routes - CRUD for users (admin only) + self-service password change.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.user import User, UserRole
from ..core.auth import get_current_user
from ..core.permissions import require_role, require_min_role

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])

templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    """Build base template context with current user info."""
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = 0
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    """Render template with base context merged in."""
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


# ============================================================
# User Management UI (Admin Only)
# ============================================================

@router.get("/users/", response_class=HTMLResponse, name="user_list",
            dependencies=[Depends(require_role("ADMIN"))])
async def user_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """User management page - list all users."""
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return _render("auth/user_management.html", request, {
        "users": users,
        "roles": [("ADMIN", "Admin"), ("ANALYST", "Analyst"), ("VIEWER", "Viewer")],
    })


# ============================================================
# User CRUD API (Admin Only)
# ============================================================

@router.get("/api/users/", name="api_user_list",
            dependencies=[Depends(require_role("ADMIN"))])
async def api_user_list(db: AsyncSession = Depends(get_db)):
    """List all users."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()

    return JSONResponse({
        "success": True,
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "failed_login_attempts": u.failed_login_attempts,
                "is_locked": u.is_locked,
            }
            for u in users
        ],
    })


@router.post("/api/users/", name="api_create_user",
             dependencies=[Depends(require_role("ADMIN"))])
async def api_create_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new user."""
    from ..schemas import CreateUserRequest
    from pydantic import ValidationError
    try:
        body = CreateUserRequest(**(await request.json()))
    except ValidationError as e:
        msg = "; ".join(err["msg"] for err in e.errors())
        return JSONResponse({"success": False, "error": msg}, status_code=400)

    username = body.username.strip()
    email = body.email
    password = body.password
    role = body.role.value

    # Check for duplicate username
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        return JSONResponse({"success": False, "error": f"Username '{username}' already exists"}, status_code=409)

    # Check for duplicate email
    if email:
        existing_email = await db.execute(select(User).where(User.email == email))
        if existing_email.scalar_one_or_none():
            return JSONResponse({"success": False, "error": f"Email '{email}' already in use"}, status_code=409)

    user = User(
        username=username,
        email=email,
        role=role,
        is_active=True,
    )
    user.set_password(password)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    from ..services.audit_service import log_from_request
    log_from_request(request, "create", "user", user.id, username, {"role": role, "email": email})

    logger.info(f"User '{username}' created by admin '{getattr(request.state, 'current_user', None)}'")

    return JSONResponse({
        "success": True,
        "message": f"User '{username}' created successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }, status_code=201)


@router.put("/api/users/{user_id}", name="api_update_user",
            dependencies=[Depends(require_role("ADMIN"))])
async def api_update_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a user (role, email, active status)."""
    body = await request.json()
    current_user = getattr(request.state, "current_user", None)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)

    # Prevent demoting the last admin
    new_role = body.get("role", user.role).upper()
    if user.role == "ADMIN" and new_role != "ADMIN":
        admin_count = await db.execute(
            select(func.count(User.id)).where(User.role == "ADMIN", User.is_active == True)
        )
        if admin_count.scalar() <= 1:
            return JSONResponse({"success": False, "error": "Cannot demote the last admin"}, status_code=400)

    # Prevent deactivating the last admin
    new_active = body.get("is_active", user.is_active)
    if user.role == "ADMIN" and not new_active and user.is_active:
        admin_count = await db.execute(
            select(func.count(User.id)).where(User.role == "ADMIN", User.is_active == True)
        )
        if admin_count.scalar() <= 1:
            return JSONResponse({"success": False, "error": "Cannot deactivate the last admin"}, status_code=400)

    # Apply updates
    if "email" in body:
        email = body["email"].strip() or None
        if email and email != user.email:
            existing_email = await db.execute(select(User).where(User.email == email, User.id != user_id))
            if existing_email.scalar_one_or_none():
                return JSONResponse({"success": False, "error": f"Email '{email}' already in use"}, status_code=409)
        user.email = email

    if "role" in body:
        if new_role in ("ADMIN", "ANALYST", "VIEWER"):
            user.role = new_role

    if "is_active" in body:
        user.is_active = bool(new_active)

    await db.commit()

    from ..services.audit_service import log_from_request
    log_from_request(request, "update", "user", user.id, user.username, {"role": user.role, "is_active": user.is_active})

    logger.info(f"User '{user.username}' updated by admin '{current_user}'")

    return JSONResponse({
        "success": True,
        "message": f"User '{user.username}' updated",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
        },
    })


@router.delete("/api/users/{user_id}", name="api_delete_user",
               dependencies=[Depends(require_role("ADMIN"))])
async def api_delete_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a user."""
    current_user = getattr(request.state, "current_user", None)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)

    # Prevent self-deletion
    if current_user and current_user.id == user_id:
        return JSONResponse({"success": False, "error": "Cannot delete your own account"}, status_code=400)

    # Prevent deleting the last admin
    if user.role == "ADMIN":
        admin_count = await db.execute(
            select(func.count(User.id)).where(User.role == "ADMIN", User.is_active == True)
        )
        if admin_count.scalar() <= 1:
            return JSONResponse({"success": False, "error": "Cannot delete the last admin"}, status_code=400)

    username = user.username
    await db.delete(user)
    await db.commit()

    from ..services.audit_service import log_from_request
    log_from_request(request, "delete", "user", user_id, username)

    logger.info(f"User '{username}' deleted by admin '{current_user}'")

    return JSONResponse({"success": True, "message": f"User '{username}' deleted"})


@router.post("/api/users/{user_id}/reset-password", name="api_reset_password",
             dependencies=[Depends(require_role("ADMIN"))])
async def api_reset_password(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Reset a user's password (admin only)."""
    from ..schemas import ResetPasswordRequest
    from pydantic import ValidationError
    try:
        body = ResetPasswordRequest(**(await request.json()))
    except ValidationError as e:
        msg = "; ".join(err["msg"] for err in e.errors())
        return JSONResponse({"success": False, "error": msg}, status_code=400)

    new_password = body.password

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)

    user.set_password(new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    from ..services.audit_service import log_from_request
    log_from_request(request, "reset_password", "user", user.id, user.username)

    logger.info(f"Password reset for user '{user.username}' by admin")

    return JSONResponse({"success": True, "message": f"Password reset for '{user.username}'"})


@router.post("/api/users/{user_id}/unlock", name="api_unlock_user",
             dependencies=[Depends(require_role("ADMIN"))])
async def api_unlock_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Unlock a locked user account."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)

    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    logger.info(f"Account unlocked for user '{user.username}'")

    return JSONResponse({"success": True, "message": f"Account '{user.username}' unlocked"})


# ============================================================
# Self-Service Endpoints (Any authenticated user)
# ============================================================

@router.get("/api/users/me", name="api_current_user")
async def api_current_user(request: Request):
    """Get current user profile."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    return JSONResponse({
        "success": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
    })


@router.put("/api/users/me/password", name="api_change_password")
async def api_change_password(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Change own password."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    from ..schemas import ChangePasswordRequest
    from pydantic import ValidationError
    try:
        body = ChangePasswordRequest(**(await request.json()))
    except ValidationError as e:
        msg = "; ".join(err["msg"] for err in e.errors())
        return JSONResponse({"success": False, "error": msg}, status_code=400)

    current_password = body.current_password
    new_password = body.new_password

    # Re-fetch user from DB to verify current password
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(current_password):
        return JSONResponse({"success": False, "error": "Current password is incorrect"}, status_code=400)

    db_user.set_password(new_password)
    await db.commit()

    logger.info(f"User '{db_user.username}' changed their password")

    return JSONResponse({"success": True, "message": "Password changed successfully"})
