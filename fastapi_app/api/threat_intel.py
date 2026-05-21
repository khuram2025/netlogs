"""
Threat Intelligence routes - feeds, IOCs, and match viewer.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.threat_intel import ThreatFeed, IOC, FeedType, IOCSighting, TIAllowlist
from ..core.permissions import require_min_role
from ..services.threat_intel_service import (
    fetch_feed, get_ioc_match_stats, get_ioc_matches_paginated,
    get_feed_match_stats,
)
from ..services.ioc_matcher import get_matcher

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat_intel"])

templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    ctx["unread_alert_count"] = 0
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


# ============================================================
# Feeds Management UI
# ============================================================

@router.get("/threat-intel/", response_class=HTMLResponse, name="threat_intel_feeds",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_intel_feeds_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Threat Intelligence feeds management page."""
    result = await db.execute(
        select(ThreatFeed).order_by(ThreatFeed.name)
    )
    feeds = result.scalars().all()

    # Get IOC counts per feed
    feed_stats = {}
    for feed in feeds:
        count_result = await db.execute(
            select(func.count(IOC.id)).where(IOC.feed_id == feed.id, IOC.is_active == True)
        )
        feed_stats[feed.id] = count_result.scalar() or 0

    # Get total active IOCs
    total_result = await db.execute(
        select(func.count(IOC.id)).where(IOC.is_active == True)
    )
    total_iocs = total_result.scalar() or 0

    # Get matcher stats
    matcher = get_matcher()
    matcher_stats = matcher.get_stats()

    # Get match stats
    match_stats = get_ioc_match_stats(hours=24)

    # Get batch-sweep coverage stats (domain/URL/hash detection)
    from ..services.ioc_sweep import get_sweep_stats
    sweep_stats = await get_sweep_stats()

    return _render("threat_intel/feeds.html", request, {
        "feeds": feeds,
        "feed_stats": feed_stats,
        "total_iocs": total_iocs,
        "matcher_stats": matcher_stats,
        "match_stats": match_stats,
        "sweep_stats": sweep_stats,
    })


# ============================================================
# IOC List UI
# ============================================================

@router.get("/threat-intel/iocs/", response_class=HTMLResponse, name="threat_intel_iocs",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_intel_iocs_page(
    request: Request,
    page: int = Query(1, ge=1),
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    feed_id: Optional[int] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """IOC list page with search and filters."""
    per_page = 50
    query = select(IOC).where(IOC.is_active == True)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if severity:
        query = query.where(IOC.severity == severity)
    if feed_id:
        query = query.where(IOC.feed_id == feed_id)
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(desc(IOC.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    iocs = result.scalars().all()

    # Get feeds for filter dropdown
    feeds_result = await db.execute(select(ThreatFeed).order_by(ThreatFeed.name))
    feeds = feeds_result.scalars().all()

    total_pages = (total + per_page - 1) // per_page

    return _render("threat_intel/iocs.html", request, {
        "iocs": iocs,
        "feeds": feeds,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "per_page": per_page,
        "filters": {
            "ioc_type": ioc_type or "",
            "severity": severity or "",
            "feed_id": feed_id or "",
            "search": search or "",
        },
    })


# ============================================================
# IOC Matches UI
# ============================================================

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@router.get("/threat-intel/matches/", response_class=HTMLResponse, name="threat_intel_matches",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_intel_matches_page(
    request: Request,
    status: str = Query("new"),
    direction: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """IOC Sightings — the de-duplicated triage queue over raw matches."""
    # Status counts for the queue tabs.
    rows = (await db.execute(
        select(IOCSighting.status, func.count(IOCSighting.id))
        .group_by(IOCSighting.status)
    )).all()
    status_counts = {r[0]: r[1] for r in rows}
    escalated_count = (await db.execute(
        select(func.count(IOCSighting.id)).where(
            IOCSighting.escalated.is_(True),
            IOCSighting.status.in_(("new", "investigating")))
    )).scalar() or 0

    # The selected queue.
    q = select(IOCSighting)
    if status == "escalated":
        q = q.where(IOCSighting.escalated.is_(True),
                    IOCSighting.status.in_(("new", "investigating")))
    elif status and status != "all":
        q = q.where(IOCSighting.status == status)
    if direction:
        q = q.where(IOCSighting.direction == direction)
    q = q.order_by(IOCSighting.escalated.desc(),
                   IOCSighting.last_seen.desc()).limit(300)
    sightings = list((await db.execute(q)).scalars().all())
    # Severity-rank within the page so the worst float up.
    sightings.sort(key=lambda s: (not s.escalated,
                                  _SEV_ORDER.get(s.severity, 9)))

    return _render("threat_intel/sightings.html", request, {
        "sightings": sightings,
        "status_counts": status_counts,
        "escalated_count": escalated_count,
        "filters": {"status": status, "direction": direction or ""},
    })


# ============================================================
# Allowlist UI
# ============================================================

@router.get("/threat-intel/allowlist/", response_class=HTMLResponse,
            name="threat_intel_allowlist",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_intel_allowlist_page(request: Request,
                                      db: AsyncSession = Depends(get_db)):
    """Allow / warning list — known-benign values that suppress sightings."""
    entries = list((await db.execute(
        select(TIAllowlist).where(TIAllowlist.is_active.is_(True))
        .order_by(TIAllowlist.list_name, TIAllowlist.entry_type,
                  TIAllowlist.value)
    )).scalars().all())
    suppressed_count = (await db.execute(
        select(func.count(IOCSighting.id)).where(
            IOCSighting.status == "suppressed")
    )).scalar() or 0
    return _render("threat_intel/allowlist.html", request, {
        "entries": entries,
        "suppressed_count": suppressed_count,
    })


# ============================================================
# API Endpoints (JSON)
# ============================================================

@router.get("/api/threat-intel/feeds/",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_feeds(db: AsyncSession = Depends(get_db)):
    """List all threat feeds."""
    result = await db.execute(select(ThreatFeed).order_by(ThreatFeed.name))
    feeds = result.scalars().all()
    return {
        "success": True,
        "feeds": [
            {
                "id": f.id,
                "name": f.name,
                "feed_type": f.feed_type,
                "url": f.url,
                "is_enabled": f.is_enabled,
                "ioc_count": f.ioc_count,
                "last_fetched_at": f.last_fetched_at.isoformat() if f.last_fetched_at else None,
                "last_fetch_status": f.last_fetch_status,
                "update_interval_minutes": f.update_interval_minutes,
            }
            for f in feeds
        ],
    }


@router.get("/api/threat-intel/feeds/{feed_id}",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_feed_detail(feed_id: int, db: AsyncSession = Depends(get_db)):
    """Get comprehensive feed detail for the feed dashboard modal."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        return JSONResponse(status_code=404, content={"success": False, "error": "Feed not found"})

    # IOC breakdown by type
    type_rows = await db.execute(
        select(IOC.ioc_type, func.count(IOC.id))
        .where(IOC.feed_id == feed_id, IOC.is_active == True)
        .group_by(IOC.ioc_type)
    )
    ioc_by_type = [{"ioc_type": r[0], "count": r[1]} for r in type_rows.all()]

    # IOC breakdown by severity
    sev_rows = await db.execute(
        select(IOC.severity, func.count(IOC.id))
        .where(IOC.feed_id == feed_id, IOC.is_active == True)
        .group_by(IOC.severity)
    )
    ioc_by_severity = [{"severity": r[0], "count": r[1]} for r in sev_rows.all()]

    # Top matched IOCs
    top_matched_rows = await db.execute(
        select(IOC.value, IOC.ioc_type, IOC.match_count, IOC.severity)
        .where(IOC.feed_id == feed_id, IOC.match_count > 0)
        .order_by(desc(IOC.match_count))
        .limit(10)
    )
    top_matched = [
        {"value": r[0], "ioc_type": r[1], "match_count": r[2], "severity": r[3]}
        for r in top_matched_rows.all()
    ]

    # Recent IOCs
    recent_ioc_rows = await db.execute(
        select(IOC.value, IOC.ioc_type, IOC.severity, IOC.confidence, IOC.created_at)
        .where(IOC.feed_id == feed_id, IOC.is_active == True)
        .order_by(desc(IOC.created_at))
        .limit(10)
    )
    recent_iocs = [
        {
            "value": r[0], "ioc_type": r[1], "severity": r[2],
            "confidence": r[3],
            "created_at": r[4].isoformat() if r[4] else None,
        }
        for r in recent_ioc_rows.all()
    ]

    # Active IOC count for this feed
    active_count_result = await db.execute(
        select(func.count(IOC.id)).where(IOC.feed_id == feed_id, IOC.is_active == True)
    )
    active_ioc_count = active_count_result.scalar() or 0

    # Match stats from ClickHouse
    match_stats = get_feed_match_stats(feed.name, hours=24)

    return {
        "success": True,
        "feed": {
            "id": feed.id,
            "name": feed.name,
            "feed_type": feed.feed_type,
            "url": feed.url,
            "is_enabled": feed.is_enabled,
            "update_interval_minutes": feed.update_interval_minutes,
            "parser_config": feed.parser_config,
            "ioc_types": feed.ioc_types,
            "ioc_count": feed.ioc_count,
            "active_ioc_count": active_ioc_count,
            "last_fetched_at": feed.last_fetched_at.isoformat() if feed.last_fetched_at else None,
            "last_fetch_status": feed.last_fetch_status,
            "last_fetch_message": feed.last_fetch_message,
            "created_at": feed.created_at.isoformat() if feed.created_at else None,
            "updated_at": feed.updated_at.isoformat() if feed.updated_at else None,
        },
        "ioc_by_type": ioc_by_type,
        "ioc_by_severity": ioc_by_severity,
        "top_matched": top_matched,
        "recent_iocs": recent_iocs,
        "match_stats": match_stats,
    }


@router.post("/api/threat-intel/feeds/",
             dependencies=[Depends(require_min_role("ADMIN"))])
async def api_create_feed(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new threat feed."""
    data = await request.json()
    feed = ThreatFeed(
        name=data["name"],
        feed_type=data.get("feed_type", "csv_url"),
        url=data.get("url"),
        is_enabled=data.get("is_enabled", True),
        update_interval_minutes=data.get("update_interval_minutes", 60),
        parser_config=data.get("parser_config", {}),
    )
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return {"success": True, "id": feed.id}


@router.put("/api/threat-intel/feeds/{feed_id}",
            dependencies=[Depends(require_min_role("ADMIN"))])
async def api_update_feed(feed_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update a threat feed."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        return JSONResponse(status_code=404, content={"success": False, "error": "Feed not found"})

    data = await request.json()
    for key in ("name", "url", "feed_type", "is_enabled", "update_interval_minutes"):
        if key in data:
            setattr(feed, key, data[key])
    if "parser_config" in data:
        feed.parser_config = data["parser_config"]

    await db.commit()
    return {"success": True}


@router.delete("/api/threat-intel/feeds/{feed_id}",
               dependencies=[Depends(require_min_role("ADMIN"))])
async def api_delete_feed(feed_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a threat feed and its IOCs."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        return JSONResponse(status_code=404, content={"success": False, "error": "Feed not found"})

    await db.delete(feed)
    await db.commit()
    return {"success": True}


@router.post("/api/threat-intel/feeds/{feed_id}/fetch",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_fetch_feed(feed_id: int, db: AsyncSession = Depends(get_db)):
    """Manually trigger a feed fetch."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        return JSONResponse(status_code=404, content={"success": False, "error": "Feed not found"})

    count, message = await fetch_feed(feed)
    return {"success": True, "imported": count, "message": message}


@router.post("/api/threat-intel/feeds/{feed_id}/toggle",
             dependencies=[Depends(require_min_role("ADMIN"))])
async def api_toggle_feed(feed_id: int, db: AsyncSession = Depends(get_db)):
    """Toggle feed enabled/disabled."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        return JSONResponse(status_code=404, content={"success": False, "error": "Feed not found"})

    feed.is_enabled = not feed.is_enabled
    await db.commit()
    return {"success": True, "is_enabled": feed.is_enabled}


# IOC Endpoints

@router.get("/api/threat-intel/iocs/",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_iocs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List IOCs with filters."""
    query = select(IOC).where(IOC.is_active == True)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if severity:
        query = query.where(IOC.severity == severity)
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(desc(IOC.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    iocs = result.scalars().all()

    return {
        "success": True,
        "total": total,
        "iocs": [
            {
                "id": i.id,
                "ioc_type": i.ioc_type,
                "value": i.value,
                "severity": i.severity,
                "confidence": i.confidence,
                "threat_type": i.threat_type,
                "source": i.source,
                "feed_id": i.feed_id,
                "match_count": i.match_count,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in iocs
        ],
    }


@router.post("/api/threat-intel/iocs/",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_add_ioc(request: Request, db: AsyncSession = Depends(get_db)):
    """Add a manual IOC."""
    data = await request.json()
    ioc = IOC(
        ioc_type=data["ioc_type"],
        value=data["value"].strip(),
        severity=data.get("severity", "medium"),
        confidence=data.get("confidence", 50),
        threat_type=data.get("threat_type", ""),
        description=data.get("description", ""),
        source="manual",
        is_active=True,
    )
    db.add(ioc)
    try:
        await db.commit()
        await db.refresh(ioc)
        return {"success": True, "id": ioc.id}
    except Exception as e:
        await db.rollback()
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})


@router.delete("/api/threat-intel/iocs/{ioc_id}",
               dependencies=[Depends(require_min_role("ANALYST"))])
async def api_delete_ioc(ioc_id: int, db: AsyncSession = Depends(get_db)):
    """Deactivate an IOC."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        return JSONResponse(status_code=404, content={"success": False, "error": "IOC not found"})

    ioc.is_active = False
    await db.commit()
    return {"success": True}


@router.post("/api/threat-intel/iocs/bulk",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_bulk_import_iocs(request: Request, db: AsyncSession = Depends(get_db)):
    """Bulk import IOCs from text input (one per line)."""
    data = await request.json()
    lines = data.get("values", "").strip().split("\n")
    ioc_type = data.get("ioc_type", "ip")
    severity = data.get("severity", "medium")
    threat_type = data.get("threat_type", "")

    imported = 0
    skipped = 0
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue

        # Check for duplicate
        existing = await db.execute(
            select(IOC).where(IOC.ioc_type == ioc_type, IOC.value == value)
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            confidence=50,
            threat_type=threat_type,
            source="manual_bulk",
            is_active=True,
        )
        db.add(ioc)
        imported += 1

    await db.commit()
    return {"success": True, "imported": imported, "skipped": skipped}


# Match Endpoints

@router.get("/api/threat-intel/matches/stats",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_match_stats(hours: int = Query(24, ge=1, le=720)):
    """Get IOC match statistics."""
    stats = get_ioc_match_stats(hours=hours)
    return {"success": True, **stats}


@router.get("/api/threat-intel/matches/",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_list_matches(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    ioc_type: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),
):
    """List IOC matches."""
    matches, total = get_ioc_matches_paginated(
        page=page, per_page=per_page, severity=severity, ioc_type=ioc_type, hours=hours
    )
    return {"success": True, "total": total, "matches": matches}


# Sighting Endpoints

_VALID_SIGHTING_STATUS = {"new", "investigating", "resolved", "false_positive"}


@router.post("/api/threat-intel/sightings/{sighting_id}/status",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_update_sighting_status(
    sighting_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    """Update a sighting's triage status (and optional notes / assignee)."""
    data = await request.json()
    new_status = (data.get("status") or "").strip()
    if new_status not in _VALID_SIGHTING_STATUS:
        return JSONResponse(status_code=400, content={
            "success": False,
            "error": f"status must be one of {sorted(_VALID_SIGHTING_STATUS)}"})
    s = (await db.execute(
        select(IOCSighting).where(IOCSighting.id == sighting_id)
    )).scalar_one_or_none()
    if not s:
        return JSONResponse(status_code=404,
                            content={"success": False, "error": "Sighting not found"})
    s.status = new_status
    if "notes" in data:
        s.notes = (data.get("notes") or "").strip() or None
    if "assigned_to" in data:
        s.assigned_to = (data.get("assigned_to") or "").strip() or None
    await db.commit()
    return {"success": True, "status": s.status}


@router.get("/api/threat-intel/sightings/{sighting_id}/events",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def api_sighting_events(sighting_id: int, db: AsyncSession = Depends(get_db)):
    """The raw ioc_matches evidence behind a sighting."""
    s = (await db.execute(
        select(IOCSighting).where(IOCSighting.id == sighting_id)
    )).scalar_one_or_none()
    if not s:
        return JSONResponse(status_code=404,
                            content={"success": False, "error": "Sighting not found"})
    from ..services.ioc_sightings import get_sighting_events
    events = await get_sighting_events(s.ioc_value, s.internal_asset, s.direction)
    return {"success": True, "events": events,
            "ioc_value": s.ioc_value, "internal_asset": s.internal_asset}


# Allowlist Endpoints

_VALID_ALLOWLIST_TYPES = {"ip", "cidr", "domain", "url", "hash"}


def _allowlist_type_for_ioc(ioc_type: str, value: str) -> str:
    """Map an IOC type to an allowlist entry_type."""
    if ioc_type == "ip":
        return "cidr" if "/" in (value or "") else "ip"
    if ioc_type == "domain":
        return "domain"
    if ioc_type == "url":
        return "url"
    return "hash"


@router.post("/api/threat-intel/allowlist/",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_add_allowlist_entry(request: Request,
                                  db: AsyncSession = Depends(get_db)):
    """Add an allow / warning-list entry."""
    data = await request.json()
    entry_type = (data.get("entry_type") or "").strip().lower()
    value = (data.get("value") or "").strip()
    if entry_type not in _VALID_ALLOWLIST_TYPES:
        return JSONResponse(status_code=400, content={
            "success": False,
            "error": f"entry_type must be one of {sorted(_VALID_ALLOWLIST_TYPES)}"})
    if not value:
        return JSONResponse(status_code=400,
                            content={"success": False, "error": "value is required"})
    dup = (await db.execute(select(TIAllowlist).where(
        TIAllowlist.entry_type == entry_type, TIAllowlist.value == value
    ))).scalar_one_or_none()
    if dup:
        if not dup.is_active:
            dup.is_active = True
            await db.commit()
        return {"success": True, "id": dup.id, "duplicate": True}
    user = getattr(request.state, "current_user", None)
    entry = TIAllowlist(
        entry_type=entry_type, value=value,
        list_name=(data.get("list_name") or "Analyst").strip() or "Analyst",
        reason=(data.get("reason") or "").strip() or None,
        source="analyst", created_by=getattr(user, "username", None),
        is_active=True,
    )
    db.add(entry)
    await db.commit()
    return {"success": True, "id": entry.id}


@router.delete("/api/threat-intel/allowlist/{entry_id}",
               dependencies=[Depends(require_min_role("ANALYST"))])
async def api_delete_allowlist_entry(entry_id: int,
                                     db: AsyncSession = Depends(get_db)):
    """Remove an allowlist entry."""
    entry = (await db.execute(select(TIAllowlist).where(
        TIAllowlist.id == entry_id))).scalar_one_or_none()
    if not entry:
        return JSONResponse(status_code=404,
                            content={"success": False, "error": "Entry not found"})
    await db.delete(entry)
    await db.commit()
    return {"success": True}


@router.post("/api/threat-intel/allowlist/from-sighting/{sighting_id}",
             dependencies=[Depends(require_min_role("ANALYST"))])
async def api_allowlist_from_sighting(sighting_id: int, request: Request,
                                      db: AsyncSession = Depends(get_db)):
    """Allowlist a sighting's IOC and suppress every open sighting for it."""
    s = (await db.execute(select(IOCSighting).where(
        IOCSighting.id == sighting_id))).scalar_one_or_none()
    if not s:
        return JSONResponse(status_code=404,
                            content={"success": False, "error": "Sighting not found"})
    entry_type = _allowlist_type_for_ioc(s.ioc_type, s.ioc_value)
    dup = (await db.execute(select(TIAllowlist).where(
        TIAllowlist.entry_type == entry_type,
        TIAllowlist.value == s.ioc_value))).scalar_one_or_none()
    if not dup:
        user = getattr(request.state, "current_user", None)
        db.add(TIAllowlist(
            entry_type=entry_type, value=s.ioc_value, list_name="Analyst",
            reason=f"False positive — allowlisted from sighting #{s.id}",
            source="analyst", created_by=getattr(user, "username", None),
            is_active=True,
        ))
    elif not dup.is_active:
        dup.is_active = True
    # Retroactively suppress every open sighting for this IOC.
    result = await db.execute(
        update(IOCSighting)
        .where(IOCSighting.ioc_value == s.ioc_value,
               IOCSighting.status.in_(("new", "investigating")))
        .values(status="suppressed", escalated=False)
    )
    await db.commit()
    return {"success": True, "suppressed": result.rowcount or 0}
