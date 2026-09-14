"""
HTMX partial endpoints — return HTML fragments for dynamic page updates.

These endpoints return raw HTML (not JSON) for HTMX to swap into the DOM.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..db.clickhouse import ClickHouseClient

router = APIRouter(prefix="/partials", tags=["partials"])
templates = Jinja2Templates(directory="fastapi_app/templates")


@router.get("/dashboard/kpis", response_class=HTMLResponse)
async def dashboard_kpis(request: Request):
    """Return KPI cards HTML fragment for HTMX swap."""
    try:
        stats = ClickHouseClient.get_dashboard_stats()
        k = stats.get("kpi", {})
    except Exception:
        k = {}

    fmt = lambda n: f"{n:,}" if isinstance(n, (int, float)) else str(n or 0)

    html = f"""
    <a class="zd-metric zd-m-blue" href="/logs/"><span class="zd-m-icon">&#128202;</span><span class="zd-m-lbl">Events (24h)</span><span class="zd-m-val">{fmt(k.get('total_24h', 0))}</span><span class="zd-m-sub">{fmt(k.get('avg_eps', 0))} avg EPS</span></a>
    <a class="zd-metric zd-m-cyan" href="/logs/"><span class="zd-m-icon">&#9889;</span><span class="zd-m-lbl">Current EPS</span><span class="zd-m-val">{fmt(k.get('current_eps', 0))}</span><span class="zd-m-sub">Events per second</span></a>
    <a class="zd-metric zd-m-green" href="/logs/?action=accept"><span class="zd-m-icon">&#9989;</span><span class="zd-m-lbl">Allowed</span><span class="zd-m-val">{fmt(k.get('allowed', 0))}</span><span class="zd-m-sub">Permitted traffic</span></a>
    <a class="zd-metric zd-m-red" href="/logs/?action=deny"><span class="zd-m-icon">&#128721;</span><span class="zd-m-lbl">Blocked</span><span class="zd-m-val">{fmt(k.get('denied', 0))}</span><span class="zd-m-sub">Denied connections</span></a>
    <a class="zd-metric zd-m-amber" href="/logs/?severity=3"><span class="zd-m-icon">&#9888;</span><span class="zd-m-lbl">Critical</span><span class="zd-m-val">{fmt(k.get('critical', 0))}</span><span class="zd-m-sub">Severity 0-3</span></a>
    <a class="zd-metric zd-m-purple" href="/logs/"><span class="zd-m-icon">&#128421;</span><span class="zd-m-lbl">Devices</span><span class="zd-m-val">{fmt(k.get('active_devices', 0))}</span><span class="zd-m-sub">Active sources</span></a>
    """
    return HTMLResponse(html)


@router.get("/logs/table", response_class=HTMLResponse)
async def logs_table_rows(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=200),
    q: Optional[str] = Query(None),
    device: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    time_range: str = Query("1h"),
):
    """Return log table rows as HTML fragment for HTMX infinite scroll / search."""
    now = datetime.now(timezone.utc)
    start_time = None

    # Parse time range
    tr = time_range.strip().lower()
    if tr.endswith('m'):
        try: start_time = now - timedelta(minutes=int(tr[:-1]))
        except ValueError: pass
    elif tr.endswith('h'):
        try: start_time = now - timedelta(hours=int(tr[:-1]))
        except ValueError: pass
    elif tr.endswith('d'):
        try: start_time = now - timedelta(days=int(tr[:-1]))
        except ValueError: pass

    if start_time is None:
        start_time = now - timedelta(hours=1)

    device_ips = [device] if device and device.strip() else None

    # Build search query from action filter
    search_query = q or ""
    if action:
        action_terms = {
            'accept': 'action:accept|allow|pass|close',
            'deny': 'action:deny|drop|block|reject',
        }
        if action in action_terms:
            search_query = f"{search_query} {action_terms[action]}".strip()

    offset = (page - 1) * per_page
    logs = ClickHouseClient.search_logs(
        limit=per_page, offset=offset,
        device_ips=device_ips,
        start_time=start_time,
        query_text=search_query if search_query else None,
    )

    sev_map = {0:'Emergency',1:'Alert',2:'Critical',3:'Error',4:'Warning',5:'Notice',6:'Info',7:'Debug'}
    sev_class = lambda s: 'badge-crit' if s <= 3 else ('badge-warn' if s == 4 else 'badge-info')

    rows_html = ""
    for log in logs:
        sev = log.get('severity', 7)
        ts = str(log.get('timestamp', ''))[:19]
        rows_html += f"""<tr>
            <td class="mono" style="white-space:nowrap;font-size:.75rem;">{ts}</td>
            <td class="ip mono">{log.get('device_ip','')}</td>
            <td class="mono">{log.get('srcip','')}</td>
            <td class="mono">{log.get('dstip','')}</td>
            <td><span class="badge-s {sev_class(sev)}">{sev_map.get(sev,'')}</span></td>
            <td>{log.get('action','')}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{log.get('policyname','')}</td>
        </tr>"""

    if not logs:
        rows_html = '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:2rem;">No logs found</td></tr>'

    # If there are more results, add an HTMX trigger row for infinite scroll
    if len(logs) == per_page:
        next_page = page + 1
        params = f"page={next_page}&per_page={per_page}&time_range={time_range}"
        if q: params += f"&q={q}"
        if device: params += f"&device={device}"
        if action: params += f"&action={action}"
        rows_html += f"""<tr hx-get="/partials/logs/table?{params}"
            hx-trigger="revealed" hx-swap="afterend" hx-target="this"
            style="height:1px;"></tr>"""

    return HTMLResponse(rows_html)


@router.get("/alerts/summary", response_class=HTMLResponse)
async def alerts_summary(request: Request):
    """Return alerts summary cards as HTML fragment."""
    try:
        from ..db.database import async_session_maker
        from ..models.alert import Alert
        from sqlalchemy import select, func

        async with async_session_maker() as session:
            total = (await session.execute(select(func.count(Alert.id)))).scalar() or 0
            new_count = (await session.execute(
                select(func.count(Alert.id)).where(Alert.status == 'new')
            )).scalar() or 0
            critical = (await session.execute(
                select(func.count(Alert.id)).where(Alert.severity == 'critical')
            )).scalar() or 0

        html = f"""
        <div class="z-badge-danger" style="font-size:1.2rem;padding:.5rem 1rem;">
            {new_count} New
        </div>
        <div class="z-badge-warning" style="font-size:1.2rem;padding:.5rem 1rem;">
            {critical} Critical
        </div>
        <div style="color:#94a3b8;font-size:.85rem;">{total} total alerts</div>
        """
        return HTMLResponse(html)
    except Exception:
        return HTMLResponse('<div style="color:#64748b;">Unable to load alerts</div>')
