"""
Scheduler Service - Background tasks for periodic routing table and zone collection.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import async_session_maker
from ..models.device import Device, ParserType, DeviceStatus
from ..models.credential import DeviceCredential
from .routing_service import RoutingService
from .zone_service import ZoneService

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: Optional[AsyncIOScheduler] = None


async def fetch_all_routing_tables():
    """
    Fetch routing tables from all Fortinet devices with configured credentials.
    This runs every hour by default.
    """
    logger.info("Starting scheduled routing table fetch for all devices")

    async with async_session_maker() as db:
        try:
            # Get all approved Fortinet devices with active SSH credentials
            result = await db.execute(
                select(Device, DeviceCredential)
                .join(DeviceCredential, Device.id == DeviceCredential.device_id)
                .where(
                    and_(
                        Device.parser == ParserType.FORTINET,
                        Device.status == DeviceStatus.APPROVED,
                        DeviceCredential.is_active == True,
                        DeviceCredential.credential_type == 'SSH'
                    )
                )
            )
            device_credentials = result.all()

            if not device_credentials:
                logger.info("No Fortinet devices with credentials found")
                return

            logger.info(f"Found {len(device_credentials)} devices to fetch routing tables from")

            success_count = 0
            error_count = 0

            for device, credential in device_credentials:
                try:
                    logger.info(f"Fetching routing tables for {device.ip_address}")
                    # Use the VDOM-aware fetch method
                    results = await RoutingService.fetch_all_vdom_routing_tables(
                        device, credential, db
                    )

                    # Count successes and failures per VDOM
                    device_success = False
                    for vdom_name, (success, message, snapshot) in results.items():
                        if success:
                            route_count = snapshot.route_count if snapshot else 0
                            logger.info(f"Successfully fetched {route_count} routes from {device.ip_address} (VDOM: {vdom_name})")
                            device_success = True
                        else:
                            logger.warning(f"Failed to fetch routes from {device.ip_address} (VDOM: {vdom_name}): {message}")

                    if device_success:
                        success_count += 1
                    else:
                        error_count += 1

                except Exception as e:
                    logger.error(f"Error fetching routing table for {device.ip_address}: {e}")
                    error_count += 1

                # Small delay between devices to avoid overloading
                await asyncio.sleep(1)

            logger.info(
                f"Scheduled routing table fetch completed: "
                f"{success_count} successful, {error_count} failed"
            )

        except Exception as e:
            logger.error(f"Error in scheduled routing table fetch: {e}")
            raise


async def fetch_all_zone_data():
    """
    Fetch zone/interface data from all Fortinet devices with configured credentials.
    This runs every hour by default.
    """
    logger.info("Starting scheduled zone data fetch for all devices")

    async with async_session_maker() as db:
        try:
            # Get all approved Fortinet devices with active SSH credentials
            result = await db.execute(
                select(Device, DeviceCredential)
                .join(DeviceCredential, Device.id == DeviceCredential.device_id)
                .where(
                    and_(
                        Device.parser == ParserType.FORTINET,
                        Device.status == DeviceStatus.APPROVED,
                        DeviceCredential.is_active == True,
                        DeviceCredential.credential_type == 'SSH'
                    )
                )
            )
            device_credentials = result.all()

            if not device_credentials:
                logger.info("No Fortinet devices with credentials found for zone fetch")
                return

            logger.info(f"Found {len(device_credentials)} devices to fetch zone data from")

            success_count = 0
            error_count = 0

            for device, credential in device_credentials:
                try:
                    logger.info(f"Fetching zone data for {device.ip_address}")
                    # Use the VDOM-aware fetch method
                    results = await ZoneService.fetch_all_vdom_zone_data(
                        device, credential, db
                    )

                    # Count successes and failures per VDOM
                    device_success = False
                    for vdom_name, (success, message, snapshot) in results.items():
                        if success:
                            zone_count = snapshot.zone_count if snapshot else 0
                            intf_count = snapshot.interface_count if snapshot else 0
                            logger.info(f"Successfully fetched {zone_count} zones, {intf_count} interfaces from {device.ip_address} (VDOM: {vdom_name})")
                            device_success = True
                        else:
                            logger.warning(f"Failed to fetch zones from {device.ip_address} (VDOM: {vdom_name}): {message}")

                    if device_success:
                        success_count += 1
                    else:
                        error_count += 1

                except Exception as e:
                    logger.error(f"Error fetching zone data for {device.ip_address}: {e}")
                    error_count += 1

                # Small delay between devices to avoid overloading
                await asyncio.sleep(1)

            logger.info(
                f"Scheduled zone data fetch completed: "
                f"{success_count} successful, {error_count} failed"
            )

        except Exception as e:
            logger.error(f"Error in scheduled zone data fetch: {e}")
            raise


def get_scheduler() -> AsyncIOScheduler:
    """Get or create the scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def start_scheduler():
    """Start the background scheduler with routing table and zone collection jobs."""
    scheduler = get_scheduler()

    # Add the hourly routing table fetch job
    scheduler.add_job(
        fetch_all_routing_tables,
        trigger=IntervalTrigger(hours=1),
        id='fetch_routing_tables',
        name='Fetch routing tables from all devices',
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )

    # Add the hourly zone/interface fetch job
    scheduler.add_job(
        fetch_all_zone_data,
        trigger=IntervalTrigger(hours=1),
        id='fetch_zone_data',
        name='Fetch zone/interface data from all devices',
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )

    # Start the scheduler
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started - routing tables and zone data will be fetched every hour")


def stop_scheduler():
    """Stop the background scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


async def trigger_routing_fetch_now():
    """Manually trigger routing table fetch for all devices."""
    logger.info("Manual trigger of routing table fetch")
    await fetch_all_routing_tables()


async def trigger_zone_fetch_now():
    """Manually trigger zone data fetch for all devices."""
    logger.info("Manual trigger of zone data fetch")
    await fetch_all_zone_data()


def get_scheduler_status() -> dict:
    """Get current scheduler status and job information."""
    scheduler = get_scheduler()

    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name,
            'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
            'trigger': str(job.trigger),
        })

    return {
        'running': scheduler.running,
        'jobs': jobs,
    }
