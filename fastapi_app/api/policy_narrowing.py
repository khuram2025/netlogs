"""
Learning Mode endpoints — analyse one device's policy against observed
traffic and return narrowing candidates. Read-only; never pushes rules.

Routes:
  GET  /devices/{device_id}/learning-mode/                         (HTML page)
  GET  /api/devices/{device_id}/policy-narrowing/                  (JSON report)
  GET  /api/devices/{device_id}/policy-narrowing/export.csv        (CSV export)
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..models.device import Device
from ..services.firewall_policy_service import FirewallPolicyService
from ..services.policy_narrowing_service import PolicyNarrowingService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["learning-mode"])


def _max_window_days() -> int:
    # ClickHouse TTL is 3 months (see clickhouse.py); cap the API at 90.
    return 90


@router.get(
    "/devices/{device_id}/learning-mode/",
    response_class=HTMLResponse,
    name="device_learning_mode",
)
async def learning_mode_page(
    request: Request,
    device_id: int,
    policy_name: Optional[str] = Query(None),
    window_days: int = Query(30, ge=1, le=90),
    vdom: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Render the Learning Mode page for a device.

    The page lets the user pick a policy from a dropdown (populated from
    the latest snapshot) and see the narrowing report inline. The actual
    analysis is fetched client-side via the JSON endpoint so the page
    stays cheap to render even when no policy is selected yet.
    """
    from .views import _render  # reuse the auth/base-context wrapper

    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        return RedirectResponse(url="/devices/")

    fw_policies = await FirewallPolicyService.get_policies(
        device_id, db, vdom=vdom, limit=1000,
    )
    # Only include rules with a name we can join on; un-named rules won't
    # match anything in syslogs.policyname.
    policies_for_select = [
        {
            "id": p.id,
            "name": p.name or f"rule-{p.rule_id}",
            "rule_id": p.rule_id,
            "action": p.action,
            "position": p.position,
            "enabled": p.enabled,
            "src_zones": p.src_zones or [],
            "dst_zones": p.dst_zones or [],
            "services": p.services or [],
            "hit_count": p.hit_count,
        }
        for p in fw_policies if (p.name or p.rule_id)
    ]

    return _render("devices/learning_mode.html", request, {
        "device": device,
        "policies": policies_for_select,
        "selected_policy_name": policy_name,
        "window_days": window_days,
        "vdom": vdom,
    })


@router.get(
    "/api/devices/{device_id}/policy-narrowing/",
    name="api_policy_narrowing",
)
async def api_policy_narrowing(
    device_id: int,
    policy_name: str = Query(..., min_length=1, max_length=255),
    window_days: int = Query(30, ge=1, le=90),
    min_hits: int = Query(5, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
):
    """Run a narrowing analysis and return a NarrowingReport as JSON."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    report = PolicyNarrowingService.analyze(
        device_ip=str(device.ip_address),
        policy_name=policy_name,
        window_days=min(window_days, _max_window_days()),
        min_hits=min_hits,
    )
    return JSONResponse(report.to_dict())


@router.get(
    "/api/devices/{device_id}/policy-narrowing/export.csv",
    name="api_policy_narrowing_export",
)
async def api_policy_narrowing_export(
    device_id: int,
    policy_name: str = Query(..., min_length=1, max_length=255),
    window_days: int = Query(30, ge=1, le=90),
    min_hits: int = Query(5, ge=1, le=10000),
    section: str = Query("candidates", pattern="^(candidates|residuals)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export the candidate or residual table as CSV."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    report = PolicyNarrowingService.analyze(
        device_ip=str(device.ip_address),
        policy_name=policy_name,
        window_days=min(window_days, _max_window_days()),
        min_hits=min_hits,
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    if section == "candidates":
        writer.writerow([
            "label", "src_zones", "dst_zones", "src_ips", "dst_ips",
            "proto", "ports", "service_group", "applications",
            "hits", "distinct_src", "distinct_dst",
            "coverage_pct", "confidence", "risk_flags",
        ])
        for c in report.candidates:
            writer.writerow([
                c.label,
                ";".join(c.src_zones), ";".join(c.dst_zones),
                ";".join(c.src_ips), ";".join(c.dst_ips),
                c.proto, ";".join(str(p) for p in c.ports),
                c.service_group or "", ";".join(c.applications),
                c.hits, c.distinct_src, c.distinct_dst,
                c.coverage_pct, c.confidence, ";".join(c.risk_flags),
            ])
    else:
        writer.writerow([
            "srcip", "dstip", "dstport", "proto", "application",
            "hits", "risk", "risk_reasons",
        ])
        for r in report.residuals:
            writer.writerow([
                r.srcip, r.dstip, r.dstport, r.proto, r.application,
                r.hits, r.risk, ";".join(r.risk_reasons),
            ])

    buf.seek(0)
    safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                         for ch in policy_name)[:60]
    filename = f"narrowing-{device_id}-{safe_name}-{section}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
