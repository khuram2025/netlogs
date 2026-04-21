"""
Compliance attestation CRUD + proof upload.

Owned by the Analytics PDF report flow — a reviewer can override the
auto-evaluated status of a compliance control (Pass / Partial / Fail /
N/A), attach a comment and an optional screenshot, and have both flow
into the printable report.

Routes:

  GET    /api/devices/{device_id}/attestations
         → list all attestations for a device (all frameworks)

  PUT    /api/devices/{device_id}/attestations/{framework}/{control_id}
         → upsert an attestation (idempotent). Accepts multipart/form-data
           so a file can ride along with the text fields in a single call.

  DELETE /api/devices/{device_id}/attestations/{framework}/{control_id}
         → clear the manual override (revert to auto). Also deletes any
           attached proof file.

Framework slugs mirror ``_compute_compliance_findings`` in views.py:
``nca_ecc | pci_dss | iso_27001 | cis_v8``.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, Depends, File, Form, HTTPException, Request, UploadFile,
)
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select, delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.auth import get_current_user
from ..db.database import get_db
from ..models.compliance_attestation import (
    ATTESTATION_STATUSES, ComplianceAttestation,
)
from ..models.device import Device

logger = logging.getLogger(__name__)

router = APIRouter()

# Proof uploads land under ``fastapi_app/static/uploads/attestations/{device_id}/``
# Using the static tree means they're already served by the app's static
# file mount — no separate handler needed.
_UPLOAD_ROOT = Path(__file__).resolve().parent.parent / "static" / "uploads" / "attestations"
_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

# Accepted MIME types for proof uploads. Deliberately narrow — a PDF
# or stray exec would waste a Policy Lookup screenshot slot.
_ALLOWED_MIME = {
    "image/png":  ".png",
    "image/jpeg": ".jpg",
    "image/jpg":  ".jpg",
    "image/webp": ".webp",
    "image/gif":  ".gif",
}
_MAX_PROOF_BYTES = 5 * 1024 * 1024  # 5 MB

# Known framework slugs — prevents an attacker from planting attestations
# under an arbitrary string that happens to map onto a filesystem path.
_ALLOWED_FRAMEWORKS = {"nca_ecc", "pci_dss", "iso_27001", "cis_v8"}


def _safe_control_segment(s: str) -> str:
    """Make a control-id safe for use in a filename."""
    # Whitelist: letters, digits, dot, dash, underscore.
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)[:64]


async def _require_device(device_id: int, db: AsyncSession) -> Device:
    d = (await db.execute(
        select(Device).where(Device.id == device_id)
    )).scalar_one_or_none()
    if d is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return d


def _serialise(a: ComplianceAttestation, *, request: Optional[Request] = None) -> dict:
    """Shape an attestation for JSON responses. ``proof_url`` is the public
    URL the browser can use to fetch the screenshot."""
    proof_url = None
    if a.proof_path:
        # proof_path is stored relative to /static — prepend the mount.
        proof_url = f"/static/{a.proof_path}"
    return {
        "id": a.id,
        "device_id": a.device_id,
        "framework": a.framework,
        "control_id": a.control_id,
        "status": a.status,
        "include_in_report": a.include_in_report,
        "notes": a.notes,
        "reviewed_by": a.reviewed_by,
        "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
        "proof_url": proof_url,
        "proof_filename": a.proof_filename,
        "proof_mimetype": a.proof_mimetype,
        "proof_size": a.proof_size,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


# ── LIST ───────────────────────────────────────────────────────────────

@router.get(
    "/devices/{device_id}/attestations",
    name="list_compliance_attestations",
)
async def list_attestations(
    device_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await _require_device(device_id, db)
    rows = (await db.execute(
        select(ComplianceAttestation)
        .where(ComplianceAttestation.device_id == device_id)
    )).scalars().all()
    return {"attestations": [_serialise(a, request=request) for a in rows]}


# ── UPSERT ─────────────────────────────────────────────────────────────

@router.put(
    "/devices/{device_id}/attestations/{framework}/{control_id:path}",
    name="upsert_compliance_attestation",
)
async def upsert_attestation(
    device_id: int,
    framework: str,
    control_id: str,
    request: Request,
    status: Optional[str] = Form(None),
    include_in_report: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    reviewed_by: Optional[str] = Form(None),
    remove_proof: Optional[str] = Form(None),
    proof: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create or update one attestation, optionally with a proof upload.

    Multipart form fields (all optional — at least one of
    ``status``/``include_in_report``/``remove_proof``/``proof``/``notes``
    should be set for the call to be meaningful):
      - ``status``            : pass | partial | fail | na (omit or leave
                                 blank to keep the auto evaluation)
      - ``include_in_report`` : "1"|"true"|"on" to include in the PDF,
                                 "0"|"false"|"off" to exclude. Default on.
      - ``notes`` (optional)  : free-form reviewer comment
      - ``reviewed_by``       : reviewer name; falls back to session user
      - ``remove_proof``      : "1" to drop any existing proof
      - ``proof`` (file)      : screenshot / scanned evidence
    """
    if framework not in _ALLOWED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")
    # status may be blank ("keep auto") or one of the allowed values.
    status_val: Optional[str] = (status or "").strip() or None
    if status_val is not None and status_val not in ATTESTATION_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status_val}")
    include_val = (include_in_report or "").strip().lower()
    if include_val in ("", "1", "true", "on", "yes"):
        include_bool = True
    elif include_val in ("0", "false", "off", "no"):
        include_bool = False
    else:
        raise HTTPException(status_code=400,
                            detail=f"Invalid include_in_report: {include_in_report!r}")
    control_id = control_id.strip()
    if not control_id or len(control_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid control_id")

    await _require_device(device_id, db)

    # Load any existing record so we can merge and retire the old proof.
    existing = (await db.execute(
        select(ComplianceAttestation).where(
            ComplianceAttestation.device_id == device_id,
            ComplianceAttestation.framework == framework,
            ComplianceAttestation.control_id == control_id,
        )
    )).scalar_one_or_none()

    # Resolve the reviewer: explicit field wins, else the session's user.
    reviewer = (reviewed_by or "").strip() or (
        getattr(current_user, "username", None)
        or getattr(current_user, "email", None)
        or "unknown"
    )

    # ── Handle proof upload ───────────────────────────────────────────
    new_proof_path = None
    new_proof_filename = None
    new_proof_mimetype = None
    new_proof_size = None
    if proof is not None and proof.filename:
        mime = (proof.content_type or "").lower()
        if mime not in _ALLOWED_MIME:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported image type: {mime!r}. Allowed: png/jpg/webp/gif.",
            )
        contents = await proof.read()
        if len(contents) > _MAX_PROOF_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Proof exceeds {_MAX_PROOF_BYTES // (1024*1024)} MB limit.",
            )
        ext = _ALLOWED_MIME[mime]
        safe_ctrl = _safe_control_segment(control_id)
        h = hashlib.sha1(contents).hexdigest()[:10]
        dev_dir = _UPLOAD_ROOT / str(device_id)
        dev_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{framework}__{safe_ctrl}__{h}{ext}"
        dest = dev_dir / filename
        dest.write_bytes(contents)
        new_proof_path = f"uploads/attestations/{device_id}/{filename}"
        new_proof_filename = proof.filename
        new_proof_mimetype = mime
        new_proof_size = len(contents)

    # ── Upsert the row ────────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    if existing is None:
        row = ComplianceAttestation(
            device_id=device_id,
            framework=framework,
            control_id=control_id,
            status=status_val,
            include_in_report=include_bool,
            notes=notes,
            reviewed_by=reviewer,
            reviewed_at=now if status_val else None,
            proof_path=new_proof_path,
            proof_filename=new_proof_filename,
            proof_mimetype=new_proof_mimetype,
            proof_size=new_proof_size,
        )
        db.add(row)
    else:
        existing.status = status_val
        existing.include_in_report = include_bool
        existing.notes = notes
        # Only update reviewer info when a status was set — include-only
        # toggles shouldn't clobber a prior attestation's signature.
        if status_val is not None:
            existing.reviewed_by = reviewer
            existing.reviewed_at = now
        # Proof handling: new upload replaces old; remove_proof=1 clears.
        if new_proof_path is not None:
            _unlink_proof(existing.proof_path)
            existing.proof_path = new_proof_path
            existing.proof_filename = new_proof_filename
            existing.proof_mimetype = new_proof_mimetype
            existing.proof_size = new_proof_size
        elif (remove_proof or "").strip() in ("1", "true", "yes", "on"):
            _unlink_proof(existing.proof_path)
            existing.proof_path = None
            existing.proof_filename = None
            existing.proof_mimetype = None
            existing.proof_size = None
        row = existing

    await db.commit()
    await db.refresh(row)
    return _serialise(row, request=request)


# ── DELETE ─────────────────────────────────────────────────────────────

@router.delete(
    "/devices/{device_id}/attestations/{framework}/{control_id:path}",
    name="delete_compliance_attestation",
)
async def delete_attestation(
    device_id: int,
    framework: str,
    control_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if framework not in _ALLOWED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")
    existing = (await db.execute(
        select(ComplianceAttestation).where(
            ComplianceAttestation.device_id == device_id,
            ComplianceAttestation.framework == framework,
            ComplianceAttestation.control_id == control_id.strip(),
        )
    )).scalar_one_or_none()
    if existing is None:
        return JSONResponse({"ok": True, "cleared": False})
    _unlink_proof(existing.proof_path)
    await db.execute(
        sa_delete(ComplianceAttestation).where(
            ComplianceAttestation.id == existing.id
        )
    )
    await db.commit()
    return {"ok": True, "cleared": True}


def _unlink_proof(relative_path: Optional[str]) -> None:
    """Best-effort delete of a proof file. Never raises — the DB row goes
    even if the file doesn't."""
    if not relative_path:
        return
    try:
        full = Path(__file__).resolve().parent.parent / "static" / relative_path
        if full.is_file():
            os.unlink(full)
    except OSError as e:
        logger.warning(f"Could not unlink proof {relative_path!r}: {e}")
