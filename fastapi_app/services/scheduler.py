"""
Scheduler Service - Background tasks for periodic routing table, zone collection,
and storage quota monitoring with automatic cleanup.
"""

import asyncio
import fcntl
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import async_session_maker
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, ParserType, DeviceStatus
from ..models.credential import DeviceCredential
from .routing_service import RoutingService
from .zone_service import ZoneService
from .alert_engine import evaluate_all_rules
from .threat_intel_service import update_all_feeds
from .ioc_matcher import refresh_ioc_cache, process_auto_block_queue
from .correlation_engine import evaluate_all_correlation_rules

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: Optional[AsyncIOScheduler] = None
_lock_file = None  # File handle for scheduler lock
SCHEDULER_LOCK_PATH = '/tmp/netlogs_scheduler.lock'


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


async def monitor_storage_quota():
    """
    Monitor storage quota and trigger automatic cleanup when needed.
    This runs every 15 minutes by default (configurable).
    """
    logger.info("Starting scheduled storage quota monitoring")

    async with async_session_maker() as db:
        try:
            from ..models.storage_settings import StorageSettings, StorageCleanupLog

            # Get settings
            result = await db.execute(select(StorageSettings).limit(1))
            settings = result.scalar_one_or_none()

            if not settings:
                logger.info("Storage settings not configured, skipping quota monitoring")
                return

            if not settings.auto_cleanup_enabled:
                logger.debug("Auto cleanup is disabled, skipping quota monitoring")
                return

            # Get current storage info
            syslogs_info = ClickHouseClient.get_syslogs_storage_info()
            current_size_gb = syslogs_info['size_gb']

            # Update current monitoring status
            settings.current_size_gb = current_size_gb
            settings.current_rows = syslogs_info['total_rows']
            settings.last_monitored_at = datetime.now(timezone.utc)

            # Calculate thresholds
            trigger_size_gb = settings.syslogs_max_size_gb * (settings.cleanup_trigger_percent / 100)
            target_size_gb = settings.syslogs_max_size_gb * (settings.cleanup_target_percent / 100)

            logger.info(
                f"Storage monitor: Current={current_size_gb:.2f}GB, "
                f"Quota={settings.syslogs_max_size_gb:.2f}GB, "
                f"Trigger={trigger_size_gb:.2f}GB ({settings.cleanup_trigger_percent}%)"
            )

            # Check if cleanup is needed
            if current_size_gb >= trigger_size_gb:
                logger.warning(
                    f"Storage quota trigger reached! Current: {current_size_gb:.2f}GB >= "
                    f"Trigger: {trigger_size_gb:.2f}GB. Initiating automatic cleanup."
                )

                # Create cleanup log entry
                cleanup_log = StorageCleanupLog(
                    triggered_by='scheduled',
                    trigger_reason=f"Quota trigger: {current_size_gb:.2f}GB >= {trigger_size_gb:.2f}GB ({settings.cleanup_trigger_percent}% of {settings.syslogs_max_size_gb:.2f}GB)",
                    size_before_gb=current_size_gb,
                    rows_before=syslogs_info['total_rows'],
                    status='started'
                )
                db.add(cleanup_log)
                await db.commit()
                await db.refresh(cleanup_log)

                # Execute cleanup
                cleanup_result = ClickHouseClient.delete_logs_to_reach_target_size(
                    target_size_gb=target_size_gb,
                    min_retention_days=settings.min_retention_days
                )

                # Update cleanup log
                cleanup_log.status = 'success' if cleanup_result['success'] else 'failed'
                cleanup_log.error_message = cleanup_result.get('message')
                cleanup_log.completed_at = datetime.now(timezone.utc)
                cleanup_log.duration_seconds = (cleanup_log.completed_at - cleanup_log.started_at).total_seconds()

                if cleanup_result.get('action_taken'):
                    cleanup_log.deletion_query = f"DELETE WHERE timestamp < now() - INTERVAL {cleanup_result.get('retention_days_used', 0)} DAY"

                # Update settings with last cleanup info
                settings.last_cleanup_at = datetime.now(timezone.utc)
                settings.last_cleanup_status = cleanup_log.status
                settings.last_cleanup_freed_gb = cleanup_result.get('estimated_freed_gb', 0)
                settings.last_cleanup_rows_deleted = cleanup_result.get('rows_affected', 0)
                settings.last_cleanup_message = cleanup_result.get('message')

                if cleanup_result['success']:
                    logger.info(
                        f"Automatic cleanup completed: Est. freed {cleanup_result.get('estimated_freed_gb', 0):.2f}GB, "
                        f"Affected ~{cleanup_result.get('rows_affected', 0):,} rows"
                    )
                else:
                    logger.error(f"Automatic cleanup failed: {cleanup_result.get('message')}")

            else:
                usage_percent = (current_size_gb / settings.syslogs_max_size_gb * 100) if settings.syslogs_max_size_gb > 0 else 0
                logger.info(f"Storage within limits: {usage_percent:.1f}% of quota used")

            await db.commit()

        except Exception as e:
            logger.error(f"Error in storage quota monitoring: {e}")
            import traceback
            traceback.print_exc()


async def check_disk_emergency():
    """
    Emergency disk check - if disk usage exceeds critical threshold,
    trigger aggressive cleanup regardless of quota settings.
    """
    import shutil

    try:
        total, used, free = shutil.disk_usage('/')
        usage_percent = (used / total) * 100

        async with async_session_maker() as db:
            from ..models.storage_settings import StorageSettings

            result = await db.execute(select(StorageSettings).limit(1))
            settings = result.scalar_one_or_none()

            critical_threshold = settings.disk_critical_percent if settings else 95.0

            if usage_percent >= critical_threshold:
                logger.critical(
                    f"DISK EMERGENCY! Usage at {usage_percent:.1f}% >= {critical_threshold}%. "
                    f"Triggering emergency cleanup!"
                )

                # Get current syslogs info
                syslogs_info = ClickHouseClient.get_syslogs_storage_info()

                # Try aggressive cleanup - delete to 50% of current size
                target_size_gb = syslogs_info['size_gb'] * 0.5
                min_days = 3  # Emergency: allow deletion down to 3 days

                cleanup_result = ClickHouseClient.delete_logs_to_reach_target_size(
                    target_size_gb=target_size_gb,
                    min_retention_days=min_days
                )

                if cleanup_result['success']:
                    logger.warning(
                        f"Emergency cleanup initiated: targeting {target_size_gb:.2f}GB, "
                        f"min retention {min_days} days"
                    )
                else:
                    logger.error(f"Emergency cleanup failed: {cleanup_result.get('message')}")

    except Exception as e:
        logger.error(f"Error in disk emergency check: {e}")


def get_scheduler() -> AsyncIOScheduler:
    """Get or create the scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def start_scheduler():
    """Start the background scheduler with routing table, zone collection, and storage monitoring jobs.

    Uses a file lock to ensure only one worker process runs the scheduler
    when uvicorn is started with multiple workers.
    """
    global _lock_file

    # Acquire exclusive lock so only one worker runs the scheduler
    try:
        _lock_file = open(SCHEDULER_LOCK_PATH, 'w')
        fcntl.flock(_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_file.write(str(os.getpid()))
        _lock_file.flush()
        logger.info(f"Scheduler lock acquired by worker PID {os.getpid()}")
    except (IOError, OSError):
        logger.info(f"Scheduler lock held by another worker, skipping scheduler start (PID {os.getpid()})")
        _lock_file = None
        return

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

    # Add alert evaluation job (every 30 seconds)
    scheduler.add_job(
        evaluate_all_rules,
        trigger=IntervalTrigger(seconds=30),
        id='evaluate_alert_rules',
        name='Evaluate alert rules against log data',
        replace_existing=True,
        max_instances=1,
    )

    # Add storage quota monitoring job (every 15 minutes)
    scheduler.add_job(
        monitor_storage_quota,
        trigger=IntervalTrigger(minutes=15),
        id='monitor_storage_quota',
        name='Monitor storage quota and trigger auto-cleanup',
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )

    # Add disk emergency check (every 5 minutes)
    scheduler.add_job(
        check_disk_emergency,
        trigger=IntervalTrigger(minutes=5),
        id='check_disk_emergency',
        name='Check for disk emergency conditions',
        replace_existing=True,
        max_instances=1,
    )

    # Add threat intelligence feed update job (every 30 minutes)
    scheduler.add_job(
        update_all_feeds,
        trigger=IntervalTrigger(minutes=30),
        id='update_threat_feeds',
        name='Update threat intelligence feeds',
        replace_existing=True,
        max_instances=1,
    )

    # Add correlation engine evaluation (every 60 seconds)
    scheduler.add_job(
        evaluate_all_correlation_rules,
        trigger=IntervalTrigger(seconds=60),
        id='evaluate_correlation_rules',
        name='Evaluate multi-stage correlation rules',
        replace_existing=True,
        max_instances=1,
    )

    # Add IOC cache refresh job (every 5 minutes)
    scheduler.add_job(
        refresh_ioc_cache,
        trigger=IntervalTrigger(minutes=5),
        id='refresh_ioc_cache',
        name='Refresh in-memory IOC matcher cache',
        replace_existing=True,
        max_instances=1,
    )

    # Add auto-block EDL queue processor (every 30 seconds)
    scheduler.add_job(
        process_auto_block_queue,
        trigger=IntervalTrigger(seconds=30),
        id='process_auto_block_queue',
        name='Process auto-block EDL queue from IOC matches',
        replace_existing=True,
        max_instances=1,
    )

    # Start the scheduler
    if not scheduler.running:
        scheduler.start()
        logger.info(
            "Scheduler started - alert engine (30s), IOC cache (5 min), "
            "storage monitoring (15 min), disk emergency check (5 min), "
            "threat feeds (30 min), routing tables/zone data (hourly)"
        )


def stop_scheduler():
    """Stop the background scheduler and release the file lock."""
    global _scheduler, _lock_file
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
    if _lock_file:
        try:
            fcntl.flock(_lock_file.fileno(), fcntl.LOCK_UN)
            _lock_file.close()
            os.unlink(SCHEDULER_LOCK_PATH)
        except (IOError, OSError):
            pass
        _lock_file = None
        logger.info("Scheduler lock released")


async def trigger_routing_fetch_now():
    """Manually trigger routing table fetch for all devices."""
    logger.info("Manual trigger of routing table fetch")
    await fetch_all_routing_tables()


async def trigger_zone_fetch_now():
    """Manually trigger zone data fetch for all devices."""
    logger.info("Manual trigger of zone data fetch")
    await fetch_all_zone_data()


async def trigger_storage_monitoring_now():
    """Manually trigger storage quota monitoring."""
    logger.info("Manual trigger of storage quota monitoring")
    await monitor_storage_quota()


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
