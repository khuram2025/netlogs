"""
Saved Searches API - save, load, share, and manage log search queries.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.saved_search import SavedSearch
from ..core.permissions import require_min_role
from ..core.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["saved_searches"])


@router.get("/api/saved-searches/", dependencies=[Depends(require_min_role("VIEWER"))])
async def list_saved_searches(request: Request, db: AsyncSession = Depends(get_db)):
    """List saved searches visible to the current user (own + shared)."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    result = await db.execute(
        select(SavedSearch).where(
            or_(
                SavedSearch.user_id == user.id,
                SavedSearch.is_shared == True,
            )
        ).order_by(SavedSearch.use_count.desc(), SavedSearch.name)
    )
    searches = result.scalars().all()

    return [{
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "query_params": s.query_params,
        "is_shared": s.is_shared,
        "is_own": s.user_id == user.id,
        "use_count": s.use_count or 0,
        "last_used_at": str(s.last_used_at) if s.last_used_at else None,
        "created_at": str(s.created_at) if s.created_at else None,
    } for s in searches]


@router.post("/api/saved-searches/", dependencies=[Depends(require_min_role("VIEWER"))])
async def create_saved_search(request: Request, db: AsyncSession = Depends(get_db)):
    """Save the current search query."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"detail": "Name is required"})

    query_params = data.get("query_params", {})
    if not query_params:
        return JSONResponse(status_code=400, content={"detail": "No search parameters to save"})

    search = SavedSearch(
        user_id=user.id,
        name=name,
        description=data.get("description", ""),
        query_params=query_params,
        is_shared=data.get("is_shared", False),
    )
    db.add(search)
    await db.commit()
    await db.refresh(search)
    return {"status": "ok", "id": search.id}


@router.post("/api/saved-searches/{search_id}/use", dependencies=[Depends(require_min_role("VIEWER"))])
async def use_saved_search(search_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Increment use count when loading a saved search."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    result = await db.execute(
        select(SavedSearch).where(
            SavedSearch.id == search_id,
            or_(SavedSearch.user_id == user.id, SavedSearch.is_shared == True),
        )
    )
    search = result.scalar_one_or_none()
    if not search:
        return JSONResponse(status_code=404, content={"detail": "Saved search not found"})

    search.use_count = (search.use_count or 0) + 1
    search.last_used_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok", "query_params": search.query_params}


@router.put("/api/saved-searches/{search_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def update_saved_search(search_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update a saved search (only owner)."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    result = await db.execute(
        select(SavedSearch).where(SavedSearch.id == search_id, SavedSearch.user_id == user.id)
    )
    search = result.scalar_one_or_none()
    if not search:
        return JSONResponse(status_code=404, content={"detail": "Saved search not found or not owned by you"})

    data = await request.json()
    if "name" in data:
        search.name = data["name"]
    if "description" in data:
        search.description = data["description"]
    if "is_shared" in data:
        search.is_shared = data["is_shared"]
    if "query_params" in data:
        search.query_params = data["query_params"]

    await db.commit()
    return {"status": "ok"}


@router.delete("/api/saved-searches/{search_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def delete_saved_search(search_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete a saved search (only owner or admin)."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    result = await db.execute(select(SavedSearch).where(SavedSearch.id == search_id))
    search = result.scalar_one_or_none()
    if not search:
        return JSONResponse(status_code=404, content={"detail": "Saved search not found"})

    # Only owner or admin can delete
    if search.user_id != user.id and user.role != "ADMIN":
        return JSONResponse(status_code=403, content={"detail": "Not authorized"})

    await db.delete(search)
    await db.commit()
    return {"status": "ok"}
