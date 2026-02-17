"""
Backup & restore API routes - Admin-only backup management.
"""

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

from ..core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["backup"])
templates = Jinja2Templates(directory="fastapi_app/templates")

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
BACKUP_DIR = Path(os.environ.get("BACKUP_PATH", Path(__file__).resolve().parents[2] / "backups"))


def _base_context(request: Request) -> dict:
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = 0
    return ctx


def _is_admin(request: Request) -> bool:
    user = getattr(request.state, "current_user", None)
    return user and user.role == "ADMIN"


def _list_backups() -> list[dict]:
    """List available backup files with metadata."""
    if not BACKUP_DIR.exists():
        return []

    backups = []
    for f in sorted(BACKUP_DIR.glob("netlogs-backup-*.tar.gz"), reverse=True):
        stat = f.stat()
        # Parse timestamp from filename: netlogs-backup-YYYYMMDD-HHMMSS.tar.gz
        name_parts = f.stem.replace(".tar", "").split("-")
        try:
            date_str = f"{name_parts[2]}-{name_parts[3]}"
            created = datetime.strptime(date_str, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
        except (IndexError, ValueError):
            created = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        size_mb = stat.st_size / (1024 * 1024)
        backups.append({
            "filename": f.name,
            "path": str(f),
            "size_bytes": stat.st_size,
            "size_display": f"{size_mb:.1f} MB" if size_mb < 1024 else f"{size_mb/1024:.1f} GB",
            "created_at": created.isoformat(),
            "created_display": created.strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
    return backups


# =========================================================================
# UI Routes
# =========================================================================

@router.get("/system/backups/", response_class=HTMLResponse, name="backups_page")
async def backups_page(request: Request):
    """Backup management page (admin only)."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    ctx = _base_context(request)
    ctx["backups"] = _list_backups()
    ctx["backup_dir"] = str(BACKUP_DIR)
    return templates.TemplateResponse("system/backups.html", ctx)


# =========================================================================
# API Routes
# =========================================================================

@router.get("/api/backups/", name="api_list_backups")
async def api_list_backups(request: Request):
    """List all available backups."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    return JSONResponse({"success": True, "backups": _list_backups()})


@router.post("/api/backups/create", name="api_create_backup")
async def api_create_backup(request: Request):
    """Trigger a manual backup. Runs the backup script."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    script = SCRIPTS_DIR / "backup.sh"
    if not script.exists():
        return JSONResponse({"error": "Backup script not found"}, status_code=500)

    logger.info("Manual backup triggered by admin")

    try:
        result = subprocess.run(
            ["bash", str(script), str(BACKUP_DIR)],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(SCRIPTS_DIR.parent),
        )

        if result.returncode != 0:
            logger.error(f"Backup failed: {result.stderr}")
            return JSONResponse({
                "success": False,
                "error": "Backup failed",
                "details": result.stderr[-500:] if result.stderr else "Unknown error",
            }, status_code=500)

        # Last line of stdout is the archive path
        lines = result.stdout.strip().split("\n")
        archive_path = lines[-1] if lines else ""

        # Log to audit
        from ..services.audit_service import log_from_request
        log_from_request(request, "create", "backup", 0, archive_path)

        logger.info(f"Backup completed: {archive_path}")
        return JSONResponse({
            "success": True,
            "message": "Backup created successfully",
            "archive": os.path.basename(archive_path),
            "log": result.stdout,
        })

    except subprocess.TimeoutExpired:
        return JSONResponse({"success": False, "error": "Backup timed out (5 min limit)"}, status_code=504)
    except Exception as e:
        logger.error(f"Backup error: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.get("/api/backups/{filename}/download", name="api_download_backup")
async def api_download_backup(filename: str, request: Request):
    """Download a backup file."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    # Sanitize filename to prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    filepath = BACKUP_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        return JSONResponse({"error": "Backup not found"}, status_code=404)

    from ..services.audit_service import log_from_request
    log_from_request(request, "download", "backup", 0, filename)

    return FileResponse(
        path=str(filepath),
        filename=filename,
        media_type="application/gzip",
    )


@router.delete("/api/backups/{filename}", name="api_delete_backup")
async def api_delete_backup(filename: str, request: Request):
    """Delete a backup file."""
    if not _is_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    if "/" in filename or "\\" in filename or ".." in filename:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    filepath = BACKUP_DIR / filename
    if not filepath.exists():
        return JSONResponse({"error": "Backup not found"}, status_code=404)

    filepath.unlink()

    from ..services.audit_service import log_from_request
    log_from_request(request, "delete", "backup", 0, filename)

    logger.info(f"Backup deleted: {filename}")
    return JSONResponse({"success": True, "message": f"Backup '{filename}' deleted"})
