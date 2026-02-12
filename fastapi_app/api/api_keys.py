"""
API Key management routes - CRUD for API keys.
Users can manage their own keys, admins can see all keys.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.api_key import APIKey
from ..models.user import User
from ..core.auth import get_current_user
from ..core.permissions import require_min_role

logger = logging.getLogger(__name__)

router = APIRouter(tags=["api_keys"])

templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = 0
    return ctx


# ============================================================
# API Key Management UI
# ============================================================

@router.get("/settings/api-keys/", response_class=HTMLResponse, name="api_keys_page")
async def api_keys_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """API key management page."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # Admins see all keys, others see only their own
    if user.role == "ADMIN":
        result = await db.execute(
            select(APIKey, User.username)
            .join(User, APIKey.user_id == User.id)
            .order_by(APIKey.created_at.desc())
        )
        keys = [{"key": k, "owner": username} for k, username in result.all()]
    else:
        result = await db.execute(
            select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
        )
        keys = [{"key": k, "owner": user.username} for k in result.scalars().all()]

    ctx = _base_context(request)
    ctx["keys"] = keys
    return templates.TemplateResponse("auth/api_keys.html", ctx)


# ============================================================
# API Key CRUD API
# ============================================================

@router.get("/api/keys/", name="api_list_keys")
async def api_list_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the current user (admin sees all)."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    if user.role == "ADMIN":
        result = await db.execute(
            select(APIKey, User.username)
            .join(User, APIKey.user_id == User.id)
            .order_by(APIKey.created_at.desc())
        )
        keys = []
        for key_obj, username in result.all():
            keys.append({
                "id": key_obj.id,
                "name": key_obj.name,
                "key_prefix": key_obj.key_prefix,
                "owner": username,
                "user_id": key_obj.user_id,
                "permissions": key_obj.permissions or ["read"],
                "is_active": key_obj.is_active,
                "last_used_at": key_obj.last_used_at.isoformat() if key_obj.last_used_at else None,
                "expires_at": key_obj.expires_at.isoformat() if key_obj.expires_at else None,
                "created_at": key_obj.created_at.isoformat() if key_obj.created_at else None,
                "is_expired": key_obj.is_expired,
            })
    else:
        result = await db.execute(
            select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
        )
        keys = []
        for key_obj in result.scalars().all():
            keys.append({
                "id": key_obj.id,
                "name": key_obj.name,
                "key_prefix": key_obj.key_prefix,
                "owner": user.username,
                "user_id": key_obj.user_id,
                "permissions": key_obj.permissions or ["read"],
                "is_active": key_obj.is_active,
                "last_used_at": key_obj.last_used_at.isoformat() if key_obj.last_used_at else None,
                "expires_at": key_obj.expires_at.isoformat() if key_obj.expires_at else None,
                "created_at": key_obj.created_at.isoformat() if key_obj.created_at else None,
                "is_expired": key_obj.is_expired,
            })

    return JSONResponse({"success": True, "keys": keys})


@router.post("/api/keys/", name="api_create_key")
async def api_create_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. Returns the full key ONCE."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    body = await request.json()
    name = body.get("name", "").strip()
    permissions = body.get("permissions", ["read"])
    expires_in_days = body.get("expires_in_days")

    if not name:
        return JSONResponse({"success": False, "error": "Key name is required"}, status_code=400)

    # Validate permissions
    valid_permissions = {"read", "write", "admin"}
    if not all(p in valid_permissions for p in permissions):
        return JSONResponse({"success": False, "error": f"Invalid permissions. Allowed: {', '.join(valid_permissions)}"}, status_code=400)

    # Non-admin users cannot create admin-permission keys
    if "admin" in permissions and user.role != "ADMIN":
        return JSONResponse({"success": False, "error": "Only admins can create keys with admin permission"}, status_code=403)

    # Limit keys per user
    key_count = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.user_id == user.id)
    )
    if key_count.scalar() >= 10:
        return JSONResponse({"success": False, "error": "Maximum 10 API keys per user"}, status_code=400)

    # Generate the key
    raw_key = APIKey.generate_key()
    key_hash = APIKey.hash_key(raw_key)
    key_prefix = raw_key[:8]

    expires_at = None
    if expires_in_days and int(expires_in_days) > 0:
        from datetime import timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(days=int(expires_in_days))

    api_key = APIKey(
        user_id=user.id,
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        permissions=permissions,
        is_active=True,
        expires_at=expires_at,
    )

    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    # Audit log
    from ..services.audit_service import log_from_request
    log_from_request(request, "create", "api_key", api_key.id, name, {"permissions": permissions})

    logger.info(f"API key '{name}' created by user '{user.username}'")

    return JSONResponse({
        "success": True,
        "message": f"API key '{name}' created. Copy the key now - it won't be shown again.",
        "key": raw_key,
        "api_key": {
            "id": api_key.id,
            "name": api_key.name,
            "key_prefix": api_key.key_prefix,
            "permissions": api_key.permissions,
            "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        },
    }, status_code=201)


@router.put("/api/keys/{key_id}", name="api_update_key")
async def api_update_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update an API key's name or permissions."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()

    if not api_key:
        return JSONResponse({"success": False, "error": "API key not found"}, status_code=404)

    # Only owner or admin can update
    if api_key.user_id != user.id and user.role != "ADMIN":
        return JSONResponse({"success": False, "error": "Not authorized"}, status_code=403)

    body = await request.json()

    if "name" in body:
        name = body["name"].strip()
        if name:
            api_key.name = name

    if "permissions" in body:
        permissions = body["permissions"]
        valid_permissions = {"read", "write", "admin"}
        if all(p in valid_permissions for p in permissions):
            if "admin" in permissions and user.role != "ADMIN":
                return JSONResponse({"success": False, "error": "Only admins can set admin permission"}, status_code=403)
            api_key.permissions = permissions

    if "is_active" in body:
        api_key.is_active = bool(body["is_active"])

    await db.commit()

    from ..services.audit_service import log_from_request
    log_from_request(request, "update", "api_key", api_key.id, api_key.name,
                     {"permissions": api_key.permissions, "is_active": api_key.is_active})

    return JSONResponse({
        "success": True,
        "message": f"API key '{api_key.name}' updated",
    })


@router.delete("/api/keys/{key_id}", name="api_delete_key")
async def api_delete_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Revoke/delete an API key."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)

    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()

    if not api_key:
        return JSONResponse({"success": False, "error": "API key not found"}, status_code=404)

    # Only owner or admin can delete
    if api_key.user_id != user.id and user.role != "ADMIN":
        return JSONResponse({"success": False, "error": "Not authorized"}, status_code=403)

    key_name = api_key.name
    await db.delete(api_key)
    await db.commit()

    from ..services.audit_service import log_from_request
    log_from_request(request, "delete", "api_key", key_id, key_name)

    logger.info(f"API key '{key_name}' deleted by '{user.username}'")

    return JSONResponse({"success": True, "message": f"API key '{key_name}' revoked"})
