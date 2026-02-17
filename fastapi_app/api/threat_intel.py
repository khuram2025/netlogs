"""
Threat Intelligence routes - feeds, IOCs, and match viewer.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.threat_intel import ThreatFeed, IOC, FeedType
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

    return _render("threat_intel/feeds.html", request, {
        "feeds": feeds,
        "feed_stats": feed_stats,
        "total_iocs": total_iocs,
        "matcher_stats": matcher_stats,
        "match_stats": match_stats,
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

@router.get("/threat-intel/matches/", response_class=HTMLResponse, name="threat_intel_matches",
            dependencies=[Depends(require_min_role("ANALYST"))])
async def threat_intel_matches_page(
    request: Request,
    severity: Optional[str] = None,
    ioc_type: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),
):
    """IOC matches viewer page."""
    matches, total = get_ioc_matches_paginated(
        page=1, per_page=100, severity=severity, ioc_type=ioc_type, hours=hours
    )
    match_stats = get_ioc_match_stats(hours=hours)

    return _render("threat_intel/matches.html", request, {
        "matches": matches,
        "total": total,
        "match_stats": match_stats,
        "filters": {
            "severity": severity or "",
            "ioc_type": ioc_type or "",
            "hours": hours,
        },
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
