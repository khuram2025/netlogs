"""
Authentication routes - login, logout, session management.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..core.auth import (
    authenticate_user,
    create_session_token,
    set_session_cookie,
    clear_session_cookie,
    get_current_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

templates = Jinja2Templates(directory="fastapi_app/templates")


@router.get("/login", response_class=HTMLResponse, name="login")
async def login_page(
    request: Request,
    next: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    """Render the login page."""
    # If already logged in, redirect to dashboard
    user = await get_current_user(request)
    if user is not None:
        return RedirectResponse(url=next or "/dashboard/", status_code=303)

    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "next_url": next or "/dashboard/",
        "error": error,
    })


@router.post("/login", name="login_post")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember_me: Optional[str] = Form(None),
    next_url: str = Form("/dashboard/"),
):
    """Handle login form submission."""
    user = await authenticate_user(username, password)

    if user is None:
        # Audit: failed login
        from ..services.audit_service import log_action
        log_action(
            username=username, action="login_failed",
            resource_type="session", details={"reason": "invalid_credentials"},
            ip_address=request.client.host if request.client else "",
        )
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "next_url": next_url,
            "error": "Invalid username or password, or account is locked.",
            "username": username,
        })

    if not user.is_active:
        return templates.TemplateResponse("auth/login.html", {
            "request": request,
            "next_url": next_url,
            "error": "Your account has been deactivated. Contact an administrator.",
            "username": username,
        })

    # Create session token
    is_remember = remember_me == "on"
    token = create_session_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        remember_me=is_remember,
    )

    # Redirect to the requested page
    redirect_url = next_url if next_url and next_url.startswith("/") else "/dashboard/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    set_session_cookie(response, token, remember_me=is_remember)

    # Audit: successful login
    from ..services.audit_service import log_action
    log_action(
        user_id=user.id, username=user.username, action="login",
        resource_type="session", resource_name=user.username,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )

    logger.info(f"User '{user.username}' logged in successfully")
    return response


@router.get("/logout", name="logout")
@router.post("/logout", name="logout_post")
async def logout(request: Request):
    """Log out the current user."""
    user = await get_current_user(request)
    if user:
        from ..services.audit_service import log_action
        log_action(
            user_id=user.id, username=user.username, action="logout",
            resource_type="session", resource_name=user.username,
            ip_address=request.client.host if request.client else "",
        )
        logger.info(f"User '{user.username}' logged out")

    response = RedirectResponse(url="/auth/login", status_code=303)
    clear_session_cookie(response)
    return response
