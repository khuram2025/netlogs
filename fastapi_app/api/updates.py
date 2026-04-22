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

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

router = APIRouter(tags=["updates"])
templates = Jinja2Templates(directory="fastapi_app/templates")

STATE_FILE = pathlib.Path(os.environ.get("ZENAI_STATE_FILE", "/opt/zenai/updater/state.json"))
AGENT_BIN  = pathlib.Path(os.environ.get("ZENAI_AGENT_BIN", "/opt/zenai/updater/agent"))
LOG_FILE   = pathlib.Path(os.environ.get("ZENAI_LOG_FILE", "/opt/zenai/updater/logs/updater.log"))
# Server the agent pulls from; overridden per environment.
DEFAULT_SERVER = os.environ.get("ZENTRYC_API", "https://zentryc.com/api/v1")
# The web process runs as a non-root user that can't drop files into
# /opt/zenai/updater/. Actions that need to poke the agent go through
# sudo into the zenai-updater user (see deploy/updater/install-updater.sh
# for the sudoers rule).
AGENT_SUDO_USER = os.environ.get("ZENAI_AGENT_SUDO_USER", "zenai-updater")
# Fields the client must never see — api_key in particular would let
# anyone who scrapes /system/updates act as this appliance against the
# OTA server.
_REDACT_FIELDS = {"api_key"}


def _base_context(request: Request) -> dict:
    ctx: dict[str, Any] = {"request": request}
    ctx["current_user"] = getattr(request.state, "current_user", None)
    ctx["unread_alert_count"] = 0
    return ctx


def _is_admin(request: Request) -> bool:
    user = getattr(request.state, "current_user", None)
    return bool(user and getattr(user, "role", None) == "ADMIN")


def _read_state_raw() -> dict:
    """Read the agent's state.json. May contain the appliance api_key."""
    # Both the `.exists()` probe and the read itself can raise
    # PermissionError when the dir is mode 0700 owned by the updater
    # user — don't let either bubble up as a 500.
    try:
        exists = STATE_FILE.exists()
    except (PermissionError, OSError) as e:
        logger.warning("updates: state path not accessible: %s", e)
        return {"_installed": False, "_error": f"cannot access {STATE_FILE}: {e}"}
    if not exists:
        return {"_installed": False}
    try:
        data = json.loads(STATE_FILE.read_text())
        data["_installed"] = True
        return data
    except (PermissionError, OSError) as e:
        logger.warning("updates: state.json unreadable: %s", e)
        return {
            "_installed": False,
            "_error": (
                "state.json is not readable by the web process. Add the web "
                "user to the zenai-updater group, then chmod 750 the dir and "
                "640 the file (see deploy/updater/install-updater.sh)."
            ),
        }
    except Exception as e:
        logger.warning("updates: state.json parse failed: %s", e)
        return {"_installed": False, "_error": str(e)}


def _redact(state: dict) -> dict:
    """Drop fields that must never leave the server (api_key, etc)."""
    return {k: v for k, v in state.items() if k not in _REDACT_FIELDS}


def _read_state() -> dict:
    """Safe state for UI/API responses — never includes api_key."""
    return _redact(_read_state_raw())


def _read_current_app_version() -> str:
    try:
        from ..__version__ import __version__
        return __version__
    except Exception:
        return "unknown"


def _read_log_tail(n_lines: int = 200) -> list[str]:
    try:
        if not LOG_FILE.exists():
            return []
    except (PermissionError, OSError):
        return []
    try:
        with open(LOG_FILE, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            read_size = min(size, 64 * 1024)
            fh.seek(size - read_size)
            data = fh.read().decode("utf-8", errors="replace")
        return data.splitlines()[-n_lines:]
    except (PermissionError, OSError) as e:
        logger.warning("updates: log tail permission denied: %s", e)
        return [f"(log not readable by web user: {e})"]
    except Exception as e:
        logger.warning("updates: log tail failed: %s", e)
        return []


def _run_agent(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Invoke the updater agent via sudo as the zenai-updater user.

    The web process runs as an unprivileged user and can't exec files
    inside /opt/zenai/updater/ directly. The deploy-time sudoers rule
    lets it drop into the zenai-updater account (and from there the
    agent can sudo to root for systemctl/apt/rsync/tar per its own
    sudoers).
    """
    cmd = ["/usr/bin/sudo", "-n", "-u", AGENT_SUDO_USER, str(AGENT_BIN), *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"agent not installed at {AGENT_BIN}"
    except subprocess.TimeoutExpired:
        return 124, "", f"agent timed out after {timeout}s"


async def _fetch_remote_latest() -> dict:
    """Ask the OTA server what release it would offer this appliance.

    Uses the raw state (with api_key) to authenticate, but returns only
    the safe subset to callers. This is what powers the "Update
    available on server" banner — distinct from the agent's cached
    `pending_release`, which only populates after a scheduled checkin.
    """
    raw = _read_state_raw()
    api_key = raw.get("api_key")
    appliance_id = raw.get("appliance_id")
    server = DEFAULT_SERVER.rstrip("/")
    if not (api_key and appliance_id):
        return {
            "ok": False,
            "error": "appliance not registered — state.json has no appliance_id / api_key",
            "server": server,
        }
    url = f"{server}/updates/check"
    headers = {
        "X-Appliance-ID": appliance_id,
        "Authorization": f"Bearer {api_key}",
    }
    # The server requires the appliance to declare its running version
    # and arch so it can decide whether to offer a release. Use the
    # agent's cached current_version (what's actually installed on the
    # host) — falling back to the live app version when the agent has
    # never applied an update (current_version still "0.0.0" on fresh
    # registrations).
    current_version = raw.get("current_version") or "0.0.0"
    params = {
        "current_version": current_version,
        "arch": raw.get("arch") or "amd64",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url, headers=headers, params=params)
    except Exception as e:
        return {"ok": False, "error": f"server unreachable: {e}", "server": server}
    if r.status_code != 200:
        return {
            "ok": False,
            "error": f"server returned {r.status_code}: {r.text[:200]}",
            "server": server,
            "status_code": r.status_code,
        }
    try:
        body = r.json()
    except Exception:
        return {"ok": False, "error": "server returned non-JSON", "server": server}
    # Normalise: endpoint shape is {"next_action": "update"|"none", "release": {...}, "subscription": {...}}
    return {
        "ok": True,
        "server": server,
        "next_action": body.get("next_action"),
        "release": body.get("release"),
        "subscription": body.get("subscription"),
    }


def _version_tuple(v: str) -> tuple:
    """Dotted version → tuple for comparison; non-numeric parts compare lex."""
    parts = []
    for chunk in (v or "").split("."):
        try:
            parts.append((0, int(chunk)))
        except ValueError:
            parts.append((1, chunk))
    return tuple(parts)


def _is_newer(candidate: str, baseline: str) -> bool:
    """True iff `candidate` is strictly greater than `baseline`."""
    if not candidate or not baseline:
        return bool(candidate and not baseline)
    try:
        return _version_tuple(candidate) > _version_tuple(baseline)
    except Exception:
        return candidate != baseline


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
    ctx["api_base"]         = DEFAULT_SERVER
    ctx["state_error"]      = state.get("_error")
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
        "api_base":        DEFAULT_SERVER,
        "agent_bin":       str(AGENT_BIN),
        "error":           state.get("_error"),
    })


@router.get("/api/system/updates/remote-latest", name="updates_api_remote_latest")
async def updates_remote_latest(request: Request):
    """Ask the OTA server, right now, what release it would ship here.

    Distinct from /status: /status returns what the agent has cached
    locally from its last checkin (could be stale up to ~15 min).
    This endpoint hits the server live and tells the UI whether a
    newer version than what's running is available, so the admin
    can choose to apply before the next scheduled checkin.
    """
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    remote = await _fetch_remote_latest()
    state = _read_state()
    app_version = _read_current_app_version()
    current_agent_version = state.get("current_version")

    available = None
    update_available = False
    if remote.get("ok") and remote.get("release"):
        release = remote["release"]
        available = release.get("version")
        # "Newer than the running app" is the honest signal for the
        # admin: the agent's current_version may still be "0.0.0" on
        # a fresh registration even though the app itself is at 3.x,
        # so compare against both and flag if either is behind.
        if available:
            update_available = (
                _is_newer(available, app_version)
                or _is_newer(available, current_agent_version or "0.0.0")
            )

    return JSONResponse({
        "ok":                    remote.get("ok", False),
        "error":                 remote.get("error"),
        "server":                remote.get("server"),
        "status_code":           remote.get("status_code"),
        "next_action":           remote.get("next_action"),
        "release":               remote.get("release"),
        "subscription":          remote.get("subscription"),
        "app_version":           app_version,
        "current_agent_version": current_agent_version,
        "available_version":     available,
        "update_available":      update_available,
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
