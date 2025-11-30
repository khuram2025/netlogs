#!/usr/bin/env python3
"""
Log Cleanup Command

Deletes old logs from ClickHouse based on per-device retention policies.

Usage:
    python -m fastapi_app.cli.cleanup_logs            # Dry run (shows what would be deleted)
    python -m fastapi_app.cli.cleanup_logs --execute  # Actually delete
    python -m fastapi_app.cli.cleanup_logs --device 192.168.1.1 --execute  # Single device

This should be run via cron:
    0 2 * * * cd /home/net/net-logs && /path/to/venv/bin/python -m fastapi_app.cli.cleanup_logs --execute
"""

import asyncio
import argparse
import logging
import sys
from datetime import datetime

from sqlalchemy import select

# Add parent directory to path
sys.path.insert(0, '/home/net/net-logs')

from fastapi_app.db.database import async_session_maker
from fastapi_app.db.clickhouse import ClickHouseClient
from fastapi_app.models.device import Device

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('cleanup_logs')


async def get_devices_with_retention(device_ip: str = None):
    """Get devices that have retention policies configured."""
    async with async_session_maker() as session:
        query = select(Device).where(Device.retention_days > 0)
        if device_ip:
            query = query.where(Device.ip_address == device_ip)

        result = await session.execute(query)
        devices = result.scalars().all()

        return [
            {
                'ip_address': d.ip_address,
                'hostname': d.hostname,
                'retention_days': d.retention_days,
            }
            for d in devices
        ]


def get_device_log_stats(device_ip: str) -> dict:
    """Get log age distribution for a device."""
    return ClickHouseClient.get_device_log_age_distribution(device_ip)


def delete_old_logs(device_ip: str, retention_days: int) -> bool:
    """Delete logs older than retention period for a device."""
    return ClickHouseClient.delete_old_logs_for_device(device_ip, retention_days)


async def cleanup_logs(execute: bool = False, device_ip: str = None):
    """Main cleanup function."""
    logger.info("=" * 60)
    logger.info("Log Cleanup Started")
    logger.info(f"Mode: {'EXECUTE' if execute else 'DRY RUN'}")
    logger.info("=" * 60)

    # Get devices with retention policies
    devices = await get_devices_with_retention(device_ip)

    if not devices:
        if device_ip:
            logger.info(f"No device found with IP {device_ip} and retention policy")
        else:
            logger.info("No devices with retention policies found")
        return

    logger.info(f"Found {len(devices)} device(s) with retention policies")
    logger.info("")

    total_logs_to_delete = 0
    devices_processed = 0

    for device in devices:
        ip = device['ip_address']
        hostname = device['hostname'] or 'Unknown'
        retention = device['retention_days']

        logger.info(f"Device: {ip} ({hostname})")
        logger.info(f"  Retention: {retention} days")

        # Get log age distribution
        stats = get_device_log_stats(ip)

        if not stats or stats.get('total', 0) == 0:
            logger.info("  No logs found for this device")
            logger.info("")
            continue

        # Calculate logs to be deleted
        logs_to_delete = stats.get('older', 0)

        if retention <= 7:
            # For 7-day retention, delete everything older than 7 days
            logs_to_delete = stats.get('last_week', 0) + stats.get('last_month', 0) + stats.get('older', 0)
        elif retention <= 30:
            # For 30-day retention, delete everything older than 30 days
            logs_to_delete = stats.get('older', 0)

        logger.info(f"  Total logs: {stats.get('total', 0):,}")
        logger.info(f"    Last 24h: {stats.get('last_24h', 0):,}")
        logger.info(f"    Last week: {stats.get('last_week', 0):,}")
        logger.info(f"    Last month: {stats.get('last_month', 0):,}")
        logger.info(f"    Older: {stats.get('older', 0):,}")
        logger.info(f"  Logs to delete: {logs_to_delete:,}")

        total_logs_to_delete += logs_to_delete

        if execute and logs_to_delete > 0:
            success = delete_old_logs(ip, retention)
            if success:
                logger.info(f"  Status: Deletion scheduled (ClickHouse mutation)")
            else:
                logger.error(f"  Status: FAILED to schedule deletion")
        elif logs_to_delete > 0:
            logger.info(f"  Status: Would delete {logs_to_delete:,} logs (dry run)")
        else:
            logger.info(f"  Status: No logs to delete")

        devices_processed += 1
        logger.info("")

    logger.info("=" * 60)
    logger.info("Summary")
    logger.info("=" * 60)
    logger.info(f"Devices processed: {devices_processed}")
    logger.info(f"Total logs {'deleted' if execute else 'to delete'}: {total_logs_to_delete:,}")

    if not execute and total_logs_to_delete > 0:
        logger.info("")
        logger.info("To actually delete logs, run with --execute flag")

    logger.info("")
    logger.info("Cleanup completed at " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def main():
    parser = argparse.ArgumentParser(
        description='Clean up old logs based on device retention policies'
    )
    parser.add_argument(
        '--execute',
        action='store_true',
        help='Actually delete logs (default: dry run)'
    )
    parser.add_argument(
        '--device',
        type=str,
        help='Only cleanup logs for specific device IP'
    )

    args = parser.parse_args()

    asyncio.run(cleanup_logs(execute=args.execute, device_ip=args.device))


if __name__ == '__main__':
    main()
