"""
First-run setup wizard routes.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from ..core.auth import (
    create_session_token,
    set_session_cookie,
    get_current_user,
    SESSION_COOKIE_NAME,
)
from ..core.config import settings
from ..db.database import async_session_maker
from ..models.user import User
from ..models.alert import NotificationChannel
from ..services.setup_service import is_setup_needed, mark_setup_complete

logger = logging.getLogger(__name__)

router = APIRouter(tags=["setup"])

templates = Jinja2Templates(directory="fastapi_app/templates")


@router.get("/setup", response_class=HTMLResponse, name="setup_wizard")
async def setup_page(request: Request):
    """Serve the setup wizard page."""
    if not await is_setup_needed():
        return RedirectResponse(url="/auth/login", status_code=303)

    return templates.TemplateResponse("setup/wizard.html", {
        "request": request,
        "syslog_port": settings.syslog_port,
    })


@router.post("/api/setup/step1")
async def setup_step1(request: Request):
    """Step 1: Change admin password and set email.
    Public endpoint — requires knowing the current default password.
    """
    if not await is_setup_needed():
        return JSONResponse({"error": "Setup already completed"}, status_code=400)

    from ..schemas import SetupStep1Request
    from pydantic import ValidationError
    try:
        body = SetupStep1Request(**(await request.json()))
    except ValidationError as e:
        msg = "; ".join(err["msg"] for err in e.errors())
        return JSONResponse({"error": msg}, status_code=400)

    current_password = body.current_password
    new_password = body.new_password
    email = body.email.strip() if body.email else ""

    # Validate current password is the default
    if current_password != "changeme":
        return JSONResponse({"error": "Current password is incorrect"}, status_code=400)

    async with async_session_maker() as session:
        result = await session.execute(
            select(User).where(User.username == "admin").limit(1)
        )
        admin = result.scalar_one_or_none()
        if not admin:
            return JSONResponse({"error": "Admin user not found"}, status_code=500)

        # Update password and email
        admin.set_password(new_password)
        if email:
            admin.email = email
        await session.commit()

        # Auto-login: create session token
        token = await create_session_token(
            user_id=admin.id,
            username=admin.username,
            role=admin.role,
        )
        response = JSONResponse({"success": True, "message": "Password updated"})
        set_session_cookie(response, token)

        logger.info("Setup wizard: admin password changed")
        return response


@router.post("/api/setup/step2")
async def setup_step2(request: Request):
    """Step 2: Configure a notification channel (optional).
    Requires auth (session from step 1).
    """
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    from ..schemas import SetupStep2Request
    from pydantic import ValidationError
    try:
        body = SetupStep2Request(**(await request.json()))
    except ValidationError as e:
        msg = "; ".join(err["msg"] for err in e.errors())
        return JSONResponse({"error": msg}, status_code=400)

    channel_type = body.channel_type
    channel_name = body.name
    config = body.config
    test = body.test

    async with async_session_maker() as session:
        channel = NotificationChannel(
            name=channel_name,
            channel_type=channel_type,
            config=config,
            is_enabled=True,
        )
        session.add(channel)
        await session.commit()
        await session.refresh(channel)

        result_data = {"success": True, "channel_id": channel.id, "message": f"{channel_type.title()} channel created"}

        # Optionally send a test notification
        if test:
            from ..services.notification_service import send_test_notification
            test_result = await send_test_notification(channel)
            result_data["test_result"] = test_result

        return JSONResponse(result_data)


@router.post("/api/setup/step3")
async def setup_step3(request: Request):
    """Step 3: Check for incoming syslog data."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        from ..db.clickhouse import ClickHouseClient
        client = ClickHouseClient.get_client()
        result = client.query(
            "SELECT count() as cnt FROM syslogs WHERE timestamp >= now() - INTERVAL 10 MINUTE"
        )
        count = result.first_row[0] if result.result_rows else 0

        return JSONResponse({
            "success": True,
            "log_count": count,
            "syslog_port": settings.syslog_port,
            "receiving": count > 0,
        })
    except Exception as e:
        logger.warning(f"Setup step3 ClickHouse check failed: {e}")
        return JSONResponse({
            "success": True,
            "log_count": 0,
            "syslog_port": settings.syslog_port,
            "receiving": False,
            "error": str(e),
        })


@router.post("/api/setup/complete")
async def setup_complete(request: Request):
    """Mark setup as complete and redirect to dashboard."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    await mark_setup_complete()

    logger.info(f"Setup wizard completed by user '{user.username}'")
    return JSONResponse({"success": True, "redirect": "/dashboard/"})
