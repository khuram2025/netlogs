"""
/system/updates — appliance update tab.

Surfaces the state of the zenai-updater agent (runs as /opt/zenai/updater/agent)
and lets an admin trigger a sync / apply / view history from the web UI.

Read-only endpoints are safe. Write endpoints shell out to the agent via a
restricted sudoers rule (see deploy/updater/install-updater.sh).

Safety: this module NEVER modifies application data. Sync triggers the agent,
which preserves .env, venv/, node_modules/, logs/, backups/, db.sqlite3 on apply.
"""

import json
import logging
import os
import pathlib
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

router = APIRouter(tags=["updates"])
templates = Jinja2Templates(directory="fastapi_app/templates")

STATE_FILE = pathlib.Path(os.environ.get("ZENAI_STATE_FILE", "/opt/zenai/updater/state.json"))
AGENT_BIN  = pathlib.Path(os.environ.get("ZENAI_AGENT_BIN", "/opt/zenai/updater/agent"))
LOG_FILE   = pathlib.Path(os.environ.get("ZENAI_LOG_FILE", "/opt/zenai/updater/logs/updater.log"))


def _base_context(request: Request) -> dict:
    ctx: dict[str, Any] = {"request": request}
    ctx["current_user"] = getattr(request.state, "current_user", None)
    ctx["unread_alert_count"] = 0
    return ctx


def _is_admin(request: Request) -> bool:
    user = getattr(request.state, "current_user", None)
    return bool(user and getattr(user, "role", None) == "ADMIN")


def _read_state() -> dict:
    if not STATE_FILE.exists():
        return {"_installed": False}
    try:
        data = json.loads(STATE_FILE.read_text())
        data["_installed"] = True
        return data
    except Exception as e:
        logger.warning("updates: state.json unreadable: %s", e)
        return {"_installed": False, "_error": str(e)}


def _read_current_app_version() -> str:
    try:
        from ..__version__ import __version__
        return __version__
    except Exception:
        return "unknown"


def _read_log_tail(n_lines: int = 200) -> list[str]:
    if not LOG_FILE.exists():
        return []
    try:
        with open(LOG_FILE, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            read_size = min(size, 64 * 1024)
            fh.seek(size - read_size)
            data = fh.read().decode("utf-8", errors="replace")
        return data.splitlines()[-n_lines:]
    except Exception as e:
        logger.warning("updates: log tail failed: %s", e)
        return []


def _run_agent(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    cmd = [str(AGENT_BIN), *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"agent not installed at {AGENT_BIN}"
    except subprocess.TimeoutExpired:
        return 124, "", f"agent timed out after {timeout}s"


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------

@router.get("/system/updates/", response_class=HTMLResponse, name="updates_page")
async def updates_page(request: Request):
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    ctx = _base_context(request)
    state = _read_state()
    ctx["updates_state"]    = state
    ctx["app_version"]      = _read_current_app_version()
    ctx["installed"]        = state.get("_installed", False)
    ctx["agent_path"]       = str(AGENT_BIN)
    ctx["state_path"]       = str(STATE_FILE)
    ctx["api_base"]         = os.environ.get("ZENTRYC_API", "https://zentryc.com/api/v1")
    return templates.TemplateResponse("system/updates.html", ctx)


# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------

@router.get("/api/system/updates/status", name="updates_api_status")
async def updates_status(request: Request):
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    state = _read_state()
    return JSONResponse({
        "installed":       state.get("_installed", False),
        "app_version":     _read_current_app_version(),
        "appliance_id":    state.get("appliance_id"),
        "current_version": state.get("current_version"),
        "last_checkin_at": state.get("last_checkin_at"),
        "last_apply_at":   state.get("last_apply_at"),
        "pending_release": state.get("pending_release"),
        "subscription":    state.get("subscription"),
        "history":         (state.get("history") or [])[:10],
        "api_base":        os.environ.get("ZENTRYC_API", "https://zentryc.com/api/v1"),
        "agent_bin":       str(AGENT_BIN),
        "error":           state.get("_error"),
    })


@router.post("/api/system/updates/sync", name="updates_api_sync")
async def updates_sync(request: Request):
    """Trigger a one-shot check-in; does NOT auto-apply."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    code, out, err = _run_agent(["once", "--dry-run"], timeout=90)
    state = _read_state()
    ok = (code == 0)
    return JSONResponse({
        "ok":              ok,
        "exit_code":       code,
        "stdout":          out[-4000:],
        "stderr":          err[-4000:],
        "pending_release": state.get("pending_release"),
        "last_checkin_at": state.get("last_checkin_at"),
    }, status_code=(200 if ok else 500))


@router.post("/api/system/updates/apply", name="updates_api_apply")
async def updates_apply(request: Request):
    """Apply a pending release the agent has already fetched in a dry-run.
    This triggers download/verify/apply on the host by the agent.
    """
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    state = _read_state()
    if not state.get("pending_release"):
        return JSONResponse({"ok": False, "error": "no pending release — run Sync first"},
                            status_code=400)

    # agent once --force: runs checkin, downloads, verifies, applies, reports.
    # Long timeout — applies can legitimately take several minutes.
    code, out, err = _run_agent(["once", "--force"], timeout=1800)
    state = _read_state()
    ok = (code == 0)
    return JSONResponse({
        "ok":             ok,
        "exit_code":      code,
        "stdout":         out[-8000:],
        "stderr":         err[-8000:],
        "current_version": state.get("current_version"),
        "last_apply_at":   state.get("last_apply_at"),
        "history":         (state.get("history") or [])[:5],
    }, status_code=(200 if ok else 500))


@router.get("/api/system/updates/logs", name="updates_api_logs")
async def updates_logs(request: Request):
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    return JSONResponse({"lines": _read_log_tail(300)})
