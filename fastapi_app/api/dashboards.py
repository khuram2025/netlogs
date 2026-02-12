"""
Custom Dashboard routes - create, view, edit dashboards with configurable widgets.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.dashboard import CustomDashboard, DashboardWidget
from ..core.permissions import require_min_role

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboards"])

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
# Dashboard List Page
# ============================================================

@router.get("/dashboards/", response_class=HTMLResponse, name="dashboard_list",
            dependencies=[Depends(require_min_role("VIEWER"))])
async def dashboard_list(request: Request, db: AsyncSession = Depends(get_db)):
    """List all dashboards visible to the current user."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(CustomDashboard).where(
            or_(
                CustomDashboard.user_id == user.id,
                CustomDashboard.is_shared == True,
            )
        ).order_by(CustomDashboard.is_default.desc(), CustomDashboard.name)
    )
    dashboards = result.scalars().all()
    return _render("dashboards/list.html", request, {"dashboards": dashboards})


@router.get("/dashboards/{dashboard_id}", response_class=HTMLResponse, name="dashboard_view",
            dependencies=[Depends(require_min_role("VIEWER"))])
async def dashboard_view(dashboard_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """View a dashboard with its widgets."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(CustomDashboard).where(
            CustomDashboard.id == dashboard_id,
            or_(CustomDashboard.user_id == user.id, CustomDashboard.is_shared == True),
        )
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        return JSONResponse(status_code=404, content={"detail": "Dashboard not found"})

    widget_result = await db.execute(
        select(DashboardWidget).where(DashboardWidget.dashboard_id == dashboard_id)
        .order_by(DashboardWidget.position_y, DashboardWidget.position_x)
    )
    widgets = widget_result.scalars().all()

    return _render("dashboards/view.html", request, {
        "dashboard": dashboard,
        "widgets": widgets,
        "is_owner": dashboard.user_id == user.id,
    })


# ============================================================
# JSON API Endpoints
# ============================================================

@router.post("/api/dashboards/", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_create_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new dashboard."""
    user = getattr(request.state, "current_user", None)
    data = await request.json()
    dashboard = CustomDashboard(
        user_id=user.id,
        name=data.get("name", "Untitled Dashboard"),
        description=data.get("description", ""),
        is_shared=data.get("is_shared", False),
    )
    db.add(dashboard)
    await db.commit()
    await db.refresh(dashboard)
    return {"status": "ok", "id": dashboard.id}


@router.put("/api/dashboards/{dashboard_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_update_dashboard(dashboard_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update dashboard properties."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(CustomDashboard).where(CustomDashboard.id == dashboard_id, CustomDashboard.user_id == user.id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        return JSONResponse(status_code=404, content={"detail": "Not found or not owned by you"})

    data = await request.json()
    if "name" in data:
        dashboard.name = data["name"]
    if "description" in data:
        dashboard.description = data["description"]
    if "is_shared" in data:
        dashboard.is_shared = data["is_shared"]
    if "is_default" in data:
        dashboard.is_default = data["is_default"]

    await db.commit()
    return {"status": "ok"}


@router.delete("/api/dashboards/{dashboard_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_delete_dashboard(dashboard_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete a dashboard and all its widgets."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(CustomDashboard).where(CustomDashboard.id == dashboard_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    if dashboard.user_id != user.id and user.role != "ADMIN":
        return JSONResponse(status_code=403, content={"detail": "Not authorized"})

    await db.delete(dashboard)
    await db.commit()
    return {"status": "ok"}


# ============================================================
# Widget API
# ============================================================

@router.post("/api/dashboards/{dashboard_id}/widgets", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_add_widget(dashboard_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Add a widget to a dashboard."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(CustomDashboard).where(CustomDashboard.id == dashboard_id, CustomDashboard.user_id == user.id)
    )
    if not result.scalar_one_or_none():
        return JSONResponse(status_code=404, content={"detail": "Dashboard not found or not owned"})

    data = await request.json()
    widget = DashboardWidget(
        dashboard_id=dashboard_id,
        widget_type=data.get("widget_type", "counter"),
        title=data.get("title", "Widget"),
        config=data.get("config", {}),
        position_x=data.get("position_x", 0),
        position_y=data.get("position_y", 0),
        width=data.get("width", 6),
        height=data.get("height", 4),
    )
    db.add(widget)
    await db.commit()
    await db.refresh(widget)
    return {"status": "ok", "id": widget.id}


@router.put("/api/dashboards/widgets/{widget_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_update_widget(widget_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Update a widget's config or position."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(
        select(DashboardWidget).where(DashboardWidget.id == widget_id)
    )
    widget = result.scalar_one_or_none()
    if not widget:
        return JSONResponse(status_code=404, content={"detail": "Widget not found"})

    # Verify ownership
    dash_result = await db.execute(
        select(CustomDashboard).where(CustomDashboard.id == widget.dashboard_id, CustomDashboard.user_id == user.id)
    )
    if not dash_result.scalar_one_or_none():
        return JSONResponse(status_code=403, content={"detail": "Not authorized"})

    data = await request.json()
    for field in ["title", "widget_type", "config", "position_x", "position_y", "width", "height"]:
        if field in data:
            setattr(widget, field, data[field])

    await db.commit()
    return {"status": "ok"}


@router.delete("/api/dashboards/widgets/{widget_id}", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_delete_widget(widget_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete a widget."""
    user = getattr(request.state, "current_user", None)
    result = await db.execute(select(DashboardWidget).where(DashboardWidget.id == widget_id))
    widget = result.scalar_one_or_none()
    if not widget:
        return JSONResponse(status_code=404, content={"detail": "Widget not found"})

    dash_result = await db.execute(
        select(CustomDashboard).where(CustomDashboard.id == widget.dashboard_id, CustomDashboard.user_id == user.id)
    )
    if not dash_result.scalar_one_or_none():
        return JSONResponse(status_code=403, content={"detail": "Not authorized"})

    await db.delete(widget)
    await db.commit()
    return {"status": "ok"}


# ============================================================
# Widget Data API
# ============================================================

@router.get("/api/dashboards/widgets/{widget_id}/data", dependencies=[Depends(require_min_role("VIEWER"))])
async def api_widget_data(widget_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch data for a widget based on its config."""
    result = await db.execute(select(DashboardWidget).where(DashboardWidget.id == widget_id))
    widget = result.scalar_one_or_none()
    if not widget:
        return JSONResponse(status_code=404, content={"detail": "Widget not found"})

    config = widget.config or {}
    try:
        data = _query_widget_data(widget.widget_type, config)
        return {"status": "ok", "data": data, "widget_type": widget.widget_type}
    except Exception as e:
        logger.error(f"Widget data error: {e}")
        return {"status": "error", "data": None, "error": str(e)}


def _query_widget_data(widget_type: str, config: dict) -> dict:
    """Execute a ClickHouse query based on widget config."""
    client = ClickHouseClient.get_client()
    data_source = config.get("data_source", "logs")
    time_range = config.get("time_range", "24h")
    query_filter = config.get("query", {})
    aggregation = config.get("aggregation", "count")
    group_by = config.get("group_by")
    limit = min(config.get("limit", 10), 100)

    # Determine table
    table = "syslogs"
    if data_source == "ioc_matches":
        table = "ioc_matches"
    elif data_source == "correlation_matches":
        table = "correlation_matches"

    # Time filter
    time_map = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080, "30d": 43200}
    minutes = time_map.get(time_range, 1440)
    time_cond = f"timestamp > now() - INTERVAL {minutes} MINUTE"

    # Build WHERE conditions
    conditions = [time_cond]
    for field, value in query_filter.items():
        if value:
            conditions.append(f"{field} = '{value}'")
    where = " AND ".join(conditions)

    if widget_type == "counter":
        # Single number
        query = f"SELECT count() FROM {table} WHERE {where}"
        result = client.query(query)
        return {"value": result.result_rows[0][0] if result.result_rows else 0}

    elif widget_type == "gauge":
        # Percentage - e.g., deny rate
        total_q = f"SELECT count() FROM {table} WHERE {time_cond}"
        filtered_q = f"SELECT count() FROM {table} WHERE {where}"
        total = client.query(total_q).result_rows[0][0]
        filtered = client.query(filtered_q).result_rows[0][0]
        pct = round(filtered / total * 100, 1) if total > 0 else 0
        return {"value": pct, "total": total, "filtered": filtered}

    elif widget_type in ("bar_chart", "doughnut"):
        # Top-N grouped by field
        if not group_by:
            group_by = "action"
        query = f"""
            SELECT {group_by}, count() as cnt
            FROM {table}
            WHERE {where}
            GROUP BY {group_by}
            ORDER BY cnt DESC
            LIMIT {limit}
        """
        result = client.query(query)
        labels = [str(r[0]) for r in result.result_rows]
        values = [r[1] for r in result.result_rows]
        return {"labels": labels, "values": values}

    elif widget_type == "line_chart":
        # Time series
        interval = "1 HOUR" if minutes > 360 else "5 MINUTE"
        if minutes > 10080:
            interval = "1 DAY"
        query = f"""
            SELECT toStartOfInterval(timestamp, INTERVAL {interval}) as ts, count() as cnt
            FROM {table}
            WHERE {where}
            GROUP BY ts
            ORDER BY ts
        """
        result = client.query(query)
        labels = [str(r[0]) for r in result.result_rows]
        values = [r[1] for r in result.result_rows]
        return {"labels": labels, "values": values}

    elif widget_type == "table":
        # Top-N table with multiple columns
        if not group_by:
            group_by = "srcip"
        query = f"""
            SELECT {group_by}, count() as cnt
            FROM {table}
            WHERE {where}
            GROUP BY {group_by}
            ORDER BY cnt DESC
            LIMIT {limit}
        """
        result = client.query(query)
        rows = [{"key": str(r[0]), "count": r[1]} for r in result.result_rows]
        return {"rows": rows, "group_by": group_by}

    return {"error": "Unknown widget type"}
