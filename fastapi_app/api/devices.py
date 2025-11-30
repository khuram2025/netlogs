"""
Device management API endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, DeviceStatus, ParserType, RetentionDays
from ..schemas.device import (
    DeviceResponse,
    DeviceUpdate,
    DeviceWithStorage,
    DeviceListResponse,
    DeviceStatusUpdate,
)

router = APIRouter(prefix="/devices", tags=["devices"])


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_number(num: int) -> str:
    """Format large numbers with commas."""
    return f"{num:,}"


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """Get list of all devices with storage statistics."""
    # Build query
    query = select(Device).order_by(Device.created_at.desc())

    if status:
        query = query.where(Device.status == status)

    result = await db.execute(query)
    devices = result.scalars().all()

    # Get per-device storage from ClickHouse
    try:
        storage_stats = ClickHouseClient.get_per_device_storage()
        storage_by_ip = {s['device_ip']: s for s in storage_stats}
    except Exception:
        storage_by_ip = {}

    # Build response
    devices_with_storage = []
    total_storage = 0
    total_logs = 0

    for device in devices:
        storage = storage_by_ip.get(device.ip_address, {})
        storage_bytes = int(storage.get('total_raw_size', 0))
        log_count = int(storage.get('log_count', 0))

        total_storage += storage_bytes
        total_logs += log_count

        device_data = DeviceWithStorage(
            id=device.id,
            ip_address=device.ip_address,
            hostname=device.hostname,
            device_type=device.device_type,
            parser=device.parser,
            retention_days=device.retention_days,
            status=device.status,
            created_at=device.created_at,
            updated_at=device.updated_at,
            last_log_received=device.last_log_received,
            log_count=device.log_count,
            status_display=device.status_display,
            parser_display=device.parser_display,
            retention_display=device.retention_display,
            is_stale=device.is_stale,
            storage_bytes=storage_bytes,
            storage_display=format_bytes(storage_bytes),
            log_count_display=format_number(log_count),
        )
        devices_with_storage.append(device_data)

    return DeviceListResponse(
        devices=devices_with_storage,
        total_count=len(devices),
        total_storage=total_storage,
        total_storage_display=format_bytes(total_storage),
        total_logs=total_logs,
    )


@router.get("/{device_id}", response_model=DeviceWithStorage)
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get a single device by ID."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get storage stats
    try:
        storage_stats = ClickHouseClient.get_per_device_storage()
        storage = next(
            (s for s in storage_stats if s['device_ip'] == device.ip_address),
            {}
        )
    except Exception:
        storage = {}

    storage_bytes = int(storage.get('total_raw_size', 0))
    log_count = int(storage.get('log_count', 0))

    return DeviceWithStorage(
        id=device.id,
        ip_address=device.ip_address,
        hostname=device.hostname,
        device_type=device.device_type,
        parser=device.parser,
        retention_days=device.retention_days,
        status=device.status,
        created_at=device.created_at,
        updated_at=device.updated_at,
        last_log_received=device.last_log_received,
        log_count=device.log_count,
        status_display=device.status_display,
        parser_display=device.parser_display,
        retention_display=device.retention_display,
        is_stale=device.is_stale,
        storage_bytes=storage_bytes,
        storage_display=format_bytes(storage_bytes),
        log_count_display=format_number(log_count),
    )


@router.post("/{device_id}/approve")
async def approve_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Approve a device for log collection."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.status = DeviceStatus.APPROVED
    await db.commit()

    return {"status": "success", "message": f"Device {device.ip_address} approved"}


@router.post("/{device_id}/reject")
async def reject_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Reject a device from log collection."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.status = DeviceStatus.REJECTED
    await db.commit()

    return {"status": "success", "message": f"Device {device.ip_address} rejected"}


@router.put("/{device_id}")
async def update_device(
    device_id: int,
    update_data: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update device settings."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if update_data.hostname is not None:
        device.hostname = update_data.hostname
    if update_data.parser is not None:
        if update_data.parser not in [p[0] for p in ParserType.CHOICES]:
            raise HTTPException(status_code=400, detail="Invalid parser type")
        device.parser = update_data.parser
    if update_data.retention_days is not None:
        if update_data.retention_days not in [r[0] for r in RetentionDays.CHOICES]:
            raise HTTPException(status_code=400, detail="Invalid retention days")
        device.retention_days = update_data.retention_days
    if update_data.device_type is not None:
        device.device_type = update_data.device_type

    await db.commit()

    return {"status": "success", "message": "Device updated"}


@router.patch("/{device_id}/status")
async def update_device_status(
    device_id: int,
    status_data: DeviceStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update device status."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.status = status_data.status
    await db.commit()

    return {"status": "success", "message": f"Device status updated to {status_data.status}"}


@router.delete("/{device_id}")
async def delete_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    await db.commit()

    return {"status": "success", "message": "Device deleted"}


@router.get("/{device_id}/log-age")
async def get_device_log_age(
    device_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get log age distribution for a device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        age_dist = ClickHouseClient.get_device_log_age_distribution(device.ip_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return age_dist


# Form-based endpoints for HTML templates
@router.post("/{device_id}/edit", response_class=RedirectResponse)
async def edit_device_form(
    device_id: int,
    hostname: str = Form(...),
    parser: str = Form(...),
    retention_days: int = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Handle device edit form submission."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.hostname = hostname
    device.parser = parser
    device.retention_days = retention_days

    await db.commit()

    return RedirectResponse(url="/devices/", status_code=303)
