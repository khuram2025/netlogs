"""API routes for External Dynamic List (EDL) management."""
import secrets
import csv
import io
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from sqlalchemy.orm import selectinload

from fastapi_app.db.database import get_db
from fastapi_app.models.edl import EDLList, EDLEntry, EDLType
from fastapi_app.schemas.edl import (
    EDLListCreate, EDLListUpdate, EDLListResponse,
    EDLEntryCreate, EDLEntryUpdate, EDLEntryResponse,
    BulkImportResult, ExportFormat,
    validate_entry_for_type
)

router = APIRouter()
templates = Jinja2Templates(directory="fastapi_app/templates")


# Custom template filters
def format_bytes(size) -> str:
    """Format bytes to human readable string."""
    if isinstance(size, str):
        try:
            size = int(size) if size else 0
        except (ValueError, TypeError):
            return "0 B"
    elif size is None:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_number(num) -> str:
    """Format large numbers with commas."""
    if num is None:
        return "0"
    return f"{num:,}"


def timesince(dt: datetime) -> str:
    """Return human-readable time since datetime."""
    if not dt:
        return "Never"
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    diff = now - dt
    seconds = int(diff.total_seconds())

    if seconds < 60:
        return f"{seconds}s ago"
    elif seconds < 3600:
        return f"{seconds // 60}m ago"
    elif seconds < 86400:
        return f"{seconds // 3600}h ago"
    else:
        return f"{seconds // 86400}d ago"


# Add custom filters to templates
templates.env.filters['format_bytes'] = format_bytes
templates.env.filters['format_number'] = format_number
templates.env.filters['timesince'] = timesince


# ============ HTML Page Routes ============

@router.get("/edl/", response_class=HTMLResponse, name="edl_list")
async def edl_list_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    list_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """Display all EDL lists."""
    query = select(EDLList).options(selectinload(EDLList.entries))

    if list_type:
        query = query.where(EDLList.list_type == list_type)

    if search:
        query = query.where(EDLList.name.ilike(f"%{search}%"))

    query = query.order_by(EDLList.created_at.desc())
    result = await db.execute(query)
    lists = result.scalars().all()

    # Get stats
    total_entries = sum(edl.entry_count for edl in lists)
    active_lists = sum(1 for edl in lists if edl.is_active)

    return templates.TemplateResponse("edl/edl_list.html", {
        "request": request,
        "lists": lists,
        "total_entries": total_entries,
        "active_lists": active_lists,
        "list_type_filter": list_type,
        "search": search or "",
        "edl_types": [e.value for e in EDLType],
    })


@router.get("/edl/new/", response_class=HTMLResponse, name="edl_create_page")
async def edl_create_page(request: Request):
    """Display form to create a new EDL list."""
    return templates.TemplateResponse("edl/edl_form.html", {
        "request": request,
        "edl": None,
        "edl_types": [e for e in EDLType],
        "is_edit": False,
    })


@router.post("/edl/new/", name="edl_create")
async def edl_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    list_type: str = Form(...),
    is_active: bool = Form(True),
    generate_token: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Create a new EDL list."""
    # Check for duplicate name
    existing = await db.execute(select(EDLList).where(EDLList.name == name.strip()))
    if existing.scalar_one_or_none():
        return templates.TemplateResponse("edl/edl_form.html", {
            "request": request,
            "edl": None,
            "edl_types": [e for e in EDLType],
            "is_edit": False,
            "error": f"A list with name '{name}' already exists.",
        })

    access_token = secrets.token_urlsafe(32) if generate_token else None

    edl = EDLList(
        name=name.strip(),
        description=description.strip() if description else None,
        list_type=EDLType(list_type),
        is_active=is_active,
        access_token=access_token,
    )
    db.add(edl)
    await db.commit()
    await db.refresh(edl)

    return RedirectResponse(url=f"/edl/{edl.id}/", status_code=303)


@router.get("/edl/{edl_id}/", response_class=HTMLResponse, name="edl_detail")
async def edl_detail_page(
    request: Request,
    edl_id: int,
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = None,
    show_inactive: bool = False,
    page: int = 1,
    per_page: int = 100,
):
    """Display EDL list details with entries."""
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.id == edl_id)
    )
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Filter entries
    entries = edl.entries
    if search:
        entries = [e for e in entries if search.lower() in e.value.lower() or (e.description and search.lower() in e.description.lower())]
    if not show_inactive:
        entries = [e for e in entries if e.is_active]

    # Sort by created_at desc
    entries = sorted(entries, key=lambda e: e.created_at, reverse=True)

    # Pagination
    total_entries = len(entries)
    total_pages = (total_entries + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    entries = entries[start:end]

    # Build feed URLs
    base_url = str(request.base_url).rstrip('/')

    # Generic feed URL (aggregated by type) - RECOMMENDED
    generic_feed_url = f"{base_url}/edl/feed/{edl.list_type.value.lower()}/"

    # Specific list feed URL - OVERRIDE
    feed_url = f"{base_url}/edl/{edl_id}/feed/"
    if edl.access_token:
        feed_url += f"?token={edl.access_token}"

    return templates.TemplateResponse("edl/edl_detail.html", {
        "request": request,
        "edl": edl,
        "entries": entries,
        "search": search or "",
        "show_inactive": show_inactive,
        "page": page,
        "per_page": per_page,
        "generic_feed_url": generic_feed_url,
        "total_entries": total_entries,
        "total_pages": total_pages,
        "feed_url": feed_url,
    })


@router.get("/edl/{edl_id}/edit/", response_class=HTMLResponse, name="edl_edit_page")
async def edl_edit_page(
    request: Request,
    edl_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Display form to edit an EDL list."""
    result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    return templates.TemplateResponse("edl/edl_form.html", {
        "request": request,
        "edl": edl,
        "edl_types": [e for e in EDLType],
        "is_edit": True,
    })


@router.post("/edl/{edl_id}/edit/", name="edl_update")
async def edl_update(
    request: Request,
    edl_id: int,
    name: str = Form(...),
    description: str = Form(None),
    is_active: bool = Form(True),
    regenerate_token: bool = Form(False),
    remove_token: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Update an EDL list."""
    result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Check for duplicate name
    if name.strip() != edl.name:
        existing = await db.execute(select(EDLList).where(EDLList.name == name.strip()))
        if existing.scalar_one_or_none():
            return templates.TemplateResponse("edl/edl_form.html", {
                "request": request,
                "edl": edl,
                "edl_types": [e for e in EDLType],
                "is_edit": True,
                "error": f"A list with name '{name}' already exists.",
            })

    edl.name = name.strip()
    edl.description = description.strip() if description else None
    edl.is_active = is_active

    if remove_token:
        edl.access_token = None
    elif regenerate_token:
        edl.access_token = secrets.token_urlsafe(32)

    await db.commit()
    return RedirectResponse(url=f"/edl/{edl_id}/", status_code=303)


@router.post("/edl/{edl_id}/delete/", name="edl_delete")
async def edl_delete(
    edl_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete an EDL list and all its entries."""
    result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    await db.delete(edl)
    await db.commit()

    return RedirectResponse(url="/edl/", status_code=303)


# ============ Entry Management Routes ============

@router.post("/edl/{edl_id}/entries/add/", name="edl_entry_add")
async def edl_entry_add(
    request: Request,
    edl_id: int,
    value: str = Form(...),
    description: str = Form(None),
    is_active: bool = Form(True),
    expires_at: str = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Add a new entry to an EDL list."""
    result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Validate entry
    is_valid, error_msg = validate_entry_for_type(value.strip(), edl.list_type)
    if not is_valid:
        return JSONResponse({"success": False, "error": error_msg}, status_code=400)

    # Check for duplicate
    existing = await db.execute(
        select(EDLEntry).where(
            EDLEntry.edl_list_id == edl_id,
            EDLEntry.value == value.strip()
        )
    )
    if existing.scalar_one_or_none():
        return JSONResponse({"success": False, "error": "Entry already exists"}, status_code=400)

    # Parse expiration date
    exp_date = None
    if expires_at:
        try:
            exp_date = datetime.fromisoformat(expires_at)
        except ValueError:
            pass

    entry = EDLEntry(
        edl_list_id=edl_id,
        value=value.strip(),
        description=description.strip() if description else None,
        is_active=is_active,
        expires_at=exp_date,
        source="manual",
    )
    db.add(entry)
    await db.commit()

    return RedirectResponse(url=f"/edl/{edl_id}/", status_code=303)


@router.post("/edl/{edl_id}/entries/{entry_id}/update/", name="edl_entry_update")
async def edl_entry_update(
    edl_id: int,
    entry_id: int,
    value: str = Form(...),
    description: str = Form(None),
    is_active: bool = Form(True),
    expires_at: str = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Update an EDL entry."""
    result = await db.execute(
        select(EDLEntry).where(
            EDLEntry.id == entry_id,
            EDLEntry.edl_list_id == edl_id
        )
    )
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    # Get list for validation
    edl_result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = edl_result.scalar_one()

    # Validate if value changed
    if value.strip() != entry.value:
        is_valid, error_msg = validate_entry_for_type(value.strip(), edl.list_type)
        if not is_valid:
            return JSONResponse({"success": False, "error": error_msg}, status_code=400)

    entry.value = value.strip()
    entry.description = description.strip() if description else None
    entry.is_active = is_active

    if expires_at:
        try:
            entry.expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            entry.expires_at = None
    else:
        entry.expires_at = None

    await db.commit()
    return RedirectResponse(url=f"/edl/{edl_id}/", status_code=303)


@router.post("/edl/{edl_id}/entries/{entry_id}/delete/", name="edl_entry_delete")
async def edl_entry_delete(
    edl_id: int,
    entry_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete an EDL entry."""
    result = await db.execute(
        select(EDLEntry).where(
            EDLEntry.id == entry_id,
            EDLEntry.edl_list_id == edl_id
        )
    )
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    await db.delete(entry)
    await db.commit()

    return RedirectResponse(url=f"/edl/{edl_id}/", status_code=303)


@router.post("/edl/{edl_id}/entries/{entry_id}/toggle/", name="edl_entry_toggle")
async def edl_entry_toggle(
    edl_id: int,
    entry_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Toggle entry active status."""
    result = await db.execute(
        select(EDLEntry).where(
            EDLEntry.id == entry_id,
            EDLEntry.edl_list_id == edl_id
        )
    )
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    entry.is_active = not entry.is_active
    await db.commit()

    return JSONResponse({"success": True, "is_active": entry.is_active})


# ============ Bulk Operations ============

@router.post("/edl/{edl_id}/import/", name="edl_import")
async def edl_bulk_import(
    request: Request,
    edl_id: int,
    file: UploadFile = File(None),
    text_input: str = Form(None),
    default_description: str = Form(None),
    overwrite: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """Bulk import entries from file or text input."""
    result = await db.execute(select(EDLList).where(EDLList.id == edl_id))
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Get entries from file or text
    entries_text = ""
    if file and file.filename:
        content = await file.read()
        entries_text = content.decode('utf-8', errors='ignore')
    elif text_input:
        entries_text = text_input
    else:
        return JSONResponse({"success": False, "error": "No input provided"}, status_code=400)

    # Parse entries (one per line)
    lines = entries_text.strip().split('\n')
    entries_to_add = []
    errors = []
    skipped = 0

    # Get existing values for duplicate check
    existing_result = await db.execute(
        select(EDLEntry.value).where(EDLEntry.edl_list_id == edl_id)
    )
    existing_values = set(row[0] for row in existing_result.fetchall())

    for i, line in enumerate(lines, 1):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue

        # Handle CSV format (value,description)
        parts = line.split(',', 1)
        value = parts[0].strip()
        description = parts[1].strip() if len(parts) > 1 else default_description

        # Validate
        is_valid, error_msg = validate_entry_for_type(value, edl.list_type)
        if not is_valid:
            errors.append(f"Line {i}: {error_msg}")
            continue

        # Check duplicate
        if value in existing_values and not overwrite:
            skipped += 1
            continue

        entries_to_add.append({
            "value": value,
            "description": description,
        })
        existing_values.add(value)

    # If overwrite, delete existing entries first
    if overwrite:
        await db.execute(delete(EDLEntry).where(EDLEntry.edl_list_id == edl_id))

    # Add new entries
    for entry_data in entries_to_add:
        entry = EDLEntry(
            edl_list_id=edl_id,
            value=entry_data["value"],
            description=entry_data["description"],
            is_active=True,
            source="import",
        )
        db.add(entry)

    await db.commit()

    import_result = BulkImportResult(
        total=len(lines),
        imported=len(entries_to_add),
        skipped=skipped,
        errors=errors[:10],  # Limit errors shown
    )

    return JSONResponse({
        "success": True,
        "imported": import_result.imported,
        "skipped": import_result.skipped,
        "errors": import_result.errors,
        "total": import_result.total,
    })


@router.get("/edl/{edl_id}/export/", name="edl_export")
async def edl_export(
    edl_id: int,
    format: str = Query("txt", description="Export format: txt, csv, json"),
    include_inactive: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    """Export EDL entries in various formats."""
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.id == edl_id)
    )
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Filter entries
    entries = edl.entries
    if not include_inactive:
        entries = [e for e in entries if e.is_effective]

    filename = f"{edl.name}_{datetime.utcnow().strftime('%Y%m%d')}"

    if format == "txt":
        # Plain text format - one entry per line
        content = "\n".join(e.value for e in entries)
        return PlainTextResponse(
            content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}.txt"'}
        )

    elif format == "csv":
        # CSV format with headers
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Value", "Description", "Active", "Expires", "Created"])
        for e in entries:
            writer.writerow([
                e.value,
                e.description or "",
                "Yes" if e.is_active else "No",
                e.expires_at.isoformat() if e.expires_at else "",
                e.created_at.isoformat(),
            ])
        content = output.getvalue()
        return PlainTextResponse(
            content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'}
        )

    elif format == "json":
        import json
        data = {
            "list_name": edl.name,
            "list_type": edl.list_type.value,
            "exported_at": datetime.utcnow().isoformat(),
            "entries": [
                {
                    "value": e.value,
                    "description": e.description,
                    "is_active": e.is_active,
                    "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                }
                for e in entries
            ]
        }
        return JSONResponse(
            data,
            headers={"Content-Disposition": f'attachment; filename="{filename}.json"'}
        )

    raise HTTPException(status_code=400, detail="Invalid export format")


@router.get("/api/edl/template/", name="edl_template")
async def edl_download_template():
    """Download import template."""
    content = """# EDL Import Template
# One entry per line
# Format: value,description (description is optional)
# Lines starting with # are comments

# IP Address examples:
192.168.1.1
10.0.0.0/8
172.16.0.1-172.16.0.255

# Domain examples:
malware.example.com
*.badsite.net

# URL examples:
http://malicious.site/path
https://phishing.example.com/login

# File Hash examples (MD5, SHA1, SHA256, SHA512):
d41d8cd98f00b204e9800998ecf8427e
da39a3ee5e6b4b0d3255bfef95601890afd80709
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
"""
    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="edl_import_template.txt"'}
    )


# ============ Feed Endpoint (For Firewalls) ============

@router.get("/edl/{edl_id}/feed/", name="edl_feed")
async def edl_feed(
    edl_id: int,
    token: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Plain text feed endpoint for firewalls.
    Returns one entry per line, suitable for FortiGate/Palo Alto EDL consumption.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.id == edl_id)
    )
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    # Check access token if required
    if edl.access_token and edl.access_token != token:
        raise HTTPException(status_code=403, detail="Invalid access token")

    # Check if list is active
    if not edl.is_active:
        raise HTTPException(status_code=403, detail="EDL list is disabled")

    # Get only active, non-expired entries
    entries = [e for e in edl.entries if e.is_effective]

    # Return plain text, one entry per line
    content = "\n".join(e.value for e in entries)

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Name": edl.name,
            "X-EDL-Type": edl.list_type.value,
            "X-EDL-Count": str(len(entries)),
        }
    )


# ============ Aggregated Feed Endpoints (All entries by type) ============

@router.get("/edl/feed/ip/", name="edl_feed_all_ip")
async def edl_feed_all_ip(
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated feed of ALL IP addresses from ALL active IP lists.
    Returns one entry per line, suitable for FortiGate/Palo Alto EDL consumption.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.list_type == EDLType.IP)
        .where(EDLList.is_active == True)
    )
    lists = result.scalars().all()

    # Collect all active, non-expired entries from all IP lists
    all_entries = set()  # Use set to avoid duplicates
    list_names = []
    for edl in lists:
        list_names.append(edl.name)
        for entry in edl.entries:
            if entry.is_effective:
                all_entries.add(entry.value)

    content = "\n".join(sorted(all_entries))

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Type": "ip",
            "X-EDL-Count": str(len(all_entries)),
            "X-EDL-Lists": ", ".join(list_names),
        }
    )


@router.get("/edl/feed/domain/", name="edl_feed_all_domain")
async def edl_feed_all_domain(
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated feed of ALL domains from ALL active Domain lists.
    Returns one entry per line, suitable for FortiGate/Palo Alto EDL consumption.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.list_type == EDLType.DOMAIN)
        .where(EDLList.is_active == True)
    )
    lists = result.scalars().all()

    # Collect all active, non-expired entries from all Domain lists
    all_entries = set()
    list_names = []
    for edl in lists:
        list_names.append(edl.name)
        for entry in edl.entries:
            if entry.is_effective:
                all_entries.add(entry.value)

    content = "\n".join(sorted(all_entries))

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Type": "domain",
            "X-EDL-Count": str(len(all_entries)),
            "X-EDL-Lists": ", ".join(list_names),
        }
    )


@router.get("/edl/feed/url/", name="edl_feed_all_url")
async def edl_feed_all_url(
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated feed of ALL URLs from ALL active URL lists.
    Returns one entry per line, suitable for FortiGate/Palo Alto EDL consumption.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.list_type == EDLType.URL)
        .where(EDLList.is_active == True)
    )
    lists = result.scalars().all()

    # Collect all active, non-expired entries from all URL lists
    all_entries = set()
    list_names = []
    for edl in lists:
        list_names.append(edl.name)
        for entry in edl.entries:
            if entry.is_effective:
                all_entries.add(entry.value)

    content = "\n".join(sorted(all_entries))

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Type": "url",
            "X-EDL-Count": str(len(all_entries)),
            "X-EDL-Lists": ", ".join(list_names),
        }
    )


@router.get("/edl/feed/hash/", name="edl_feed_all_hash")
async def edl_feed_all_hash(
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated feed of ALL file hashes from ALL active Hash lists.
    Returns one entry per line, suitable for Palo Alto WildFire/threat intelligence.
    Supports MD5, SHA1, SHA256, and SHA512 hashes.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.list_type == EDLType.HASH)
        .where(EDLList.is_active == True)
    )
    lists = result.scalars().all()

    # Collect all active, non-expired entries from all Hash lists
    all_entries = set()
    list_names = []
    for edl in lists:
        list_names.append(edl.name)
        for entry in edl.entries:
            if entry.is_effective:
                all_entries.add(entry.value.lower())  # Normalize to lowercase

    content = "\n".join(sorted(all_entries))

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Type": "hash",
            "X-EDL-Count": str(len(all_entries)),
            "X-EDL-Lists": ", ".join(list_names),
        }
    )


@router.get("/edl/feed/all/", name="edl_feed_all")
async def edl_feed_all(
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated feed of ALL entries from ALL active lists (all types combined).
    Returns one entry per line.
    """
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.is_active == True)
    )
    lists = result.scalars().all()

    # Collect all active, non-expired entries
    all_entries = set()
    stats = {"ip": 0, "domain": 0, "url": 0, "hash": 0}
    for edl in lists:
        for entry in edl.entries:
            if entry.is_effective:
                all_entries.add(entry.value)
                stats[edl.list_type.value] = stats.get(edl.list_type.value, 0) + 1

    content = "\n".join(sorted(all_entries))

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-EDL-Type": "all",
            "X-EDL-Count": str(len(all_entries)),
            "X-EDL-IP-Count": str(stats["ip"]),
            "X-EDL-Domain-Count": str(stats["domain"]),
            "X-EDL-URL-Count": str(stats["url"]),
            "X-EDL-Hash-Count": str(stats["hash"]),
        }
    )


# ============ API Endpoints (JSON) ============

@router.get("/api/edl/", name="api_edl_list")
async def api_edl_list(
    db: AsyncSession = Depends(get_db),
    list_type: Optional[str] = None,
):
    """Get all EDL lists as JSON."""
    query = select(EDLList).options(selectinload(EDLList.entries))

    if list_type:
        query = query.where(EDLList.list_type == list_type)

    result = await db.execute(query.order_by(EDLList.created_at.desc()))
    lists = result.scalars().all()

    return [
        {
            "id": edl.id,
            "name": edl.name,
            "description": edl.description,
            "list_type": edl.list_type.value,
            "is_active": edl.is_active,
            "entry_count": edl.entry_count,
            "active_entry_count": edl.active_entry_count,
            "created_at": edl.created_at.isoformat(),
            "updated_at": edl.updated_at.isoformat(),
        }
        for edl in lists
    ]


@router.get("/api/edl/{edl_id}/", name="api_edl_detail")
async def api_edl_detail(
    edl_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get EDL list details with entries as JSON."""
    result = await db.execute(
        select(EDLList)
        .options(selectinload(EDLList.entries))
        .where(EDLList.id == edl_id)
    )
    edl = result.scalar_one_or_none()

    if not edl:
        raise HTTPException(status_code=404, detail="EDL list not found")

    return {
        "id": edl.id,
        "name": edl.name,
        "description": edl.description,
        "list_type": edl.list_type.value,
        "is_active": edl.is_active,
        "entry_count": edl.entry_count,
        "created_at": edl.created_at.isoformat(),
        "updated_at": edl.updated_at.isoformat(),
        "entries": [
            {
                "id": e.id,
                "value": e.value,
                "description": e.description,
                "is_active": e.is_active,
                "is_expired": e.is_expired,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "created_at": e.created_at.isoformat(),
            }
            for e in edl.entries
        ]
    }


@router.post("/edl/{edl_id}/entries/bulk-delete/", name="edl_bulk_delete")
async def edl_bulk_delete(
    edl_id: int,
    entry_ids: List[int] = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Bulk delete entries."""
    await db.execute(
        delete(EDLEntry).where(
            EDLEntry.edl_list_id == edl_id,
            EDLEntry.id.in_(entry_ids)
        )
    )
    await db.commit()
    return JSONResponse({"success": True, "deleted": len(entry_ids)})


@router.post("/edl/{edl_id}/entries/bulk-toggle/", name="edl_bulk_toggle")
async def edl_bulk_toggle(
    edl_id: int,
    entry_ids: List[int] = Form(...),
    is_active: bool = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Bulk toggle entry status."""
    result = await db.execute(
        select(EDLEntry).where(
            EDLEntry.edl_list_id == edl_id,
            EDLEntry.id.in_(entry_ids)
        )
    )
    entries = result.scalars().all()

    for entry in entries:
        entry.is_active = is_active

    await db.commit()
    return JSONResponse({"success": True, "updated": len(entries)})
