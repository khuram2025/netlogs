#!/usr/bin/env python3
"""
Disk cleanup script for ClickHouse storage management.

Monitors disk usage and automatically cleans up ClickHouse system tables
and old log data to prevent the drive from reaching 100% capacity.

Usage:
    python -m fastapi_app.cli.disk_cleanup --threshold 90 --dry-run
    python -m fastapi_app.cli.disk_cleanup --threshold 90
"""

import argparse
import logging
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import clickhouse_connect

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/home/net/zentryc/logs/disk_cleanup.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


# Load settings from .env file or environment
import os
from pathlib import Path

# Try to load .env file
env_path = Path('/home/net/zentryc/.env')
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())

# ClickHouse connection settings
CLICKHOUSE_HOST = os.environ.get('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.environ.get('CLICKHOUSE_PORT', 8123))
CLICKHOUSE_USER = os.environ.get('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', 'password')
CLICKHOUSE_DB = os.environ.get('CLICKHOUSE_DB', 'default')


def get_disk_usage(path: str = '/') -> Dict[str, any]:
    """Get disk usage statistics for the specified path."""
    total, used, free = shutil.disk_usage(path)
    usage_percent = (used / total) * 100
    return {
        'total_gb': total / (1024**3),
        'used_gb': used / (1024**3),
        'free_gb': free / (1024**3),
        'usage_percent': usage_percent
    }


def get_clickhouse_client():
    """Create ClickHouse client connection."""
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DB,
    )


def get_table_sizes(client) -> List[Dict]:
    """Get all ClickHouse tables sorted by size."""
    query = """
    SELECT
        database,
        table,
        sum(bytes_on_disk) AS total_bytes,
        sum(rows) AS total_rows,
        formatReadableSize(sum(bytes_on_disk)) AS size_readable
    FROM system.parts
    WHERE active
    GROUP BY database, table
    ORDER BY total_bytes DESC
    """
    result = list(client.query(query).named_results())
    return result


def get_system_tables_to_clean() -> List[Tuple[str, str]]:
    """
    Return list of system tables that can be safely truncated.
    Format: (database, table)
    Priority order: largest impact first.
    """
    return [
        ('system', 'trace_log'),
        ('system', 'text_log'),
        ('system', 'query_log'),
        ('system', 'metric_log'),
        ('system', 'part_log'),
        ('system', 'asynchronous_metric_log'),
        ('system', 'processors_profile_log'),
        ('system', 'query_metric_log'),
        ('system', 'asynchronous_insert_log'),
        ('system', 'error_log'),
    ]


def truncate_table(client, database: str, table: str, dry_run: bool = False) -> bool:
    """Truncate a ClickHouse table."""
    try:
        if dry_run:
            logger.info(f"[DRY-RUN] Would truncate {database}.{table}")
            return True

        query = f"TRUNCATE TABLE {database}.{table}"
        client.command(query)
        logger.info(f"Truncated {database}.{table}")
        return True
    except Exception as e:
        logger.warning(f"Failed to truncate {database}.{table}: {e}")
        return False


def delete_old_syslogs(client, days: int = 30, dry_run: bool = False) -> int:
    """
    Delete syslogs older than specified days.
    Returns approximate number of rows deleted.
    """
    try:
        # First count how many rows would be deleted
        count_query = f"""
        SELECT count() as count
        FROM syslogs
        WHERE timestamp < now() - INTERVAL {days} DAY
        """
        result = client.query(count_query).result_rows
        count = result[0][0] if result else 0

        if count == 0:
            logger.info(f"No syslogs older than {days} days to delete")
            return 0

        if dry_run:
            logger.info(f"[DRY-RUN] Would delete ~{count:,} syslogs older than {days} days")
            return count

        # Execute deletion
        delete_query = f"""
        ALTER TABLE syslogs DELETE
        WHERE timestamp < now() - INTERVAL {days} DAY
        """
        client.command(delete_query)
        logger.info(f"Scheduled deletion of ~{count:,} syslogs older than {days} days")
        return count

    except Exception as e:
        logger.error(f"Failed to delete old syslogs: {e}")
        return 0


def optimize_tables(client, dry_run: bool = False) -> None:
    """Run OPTIMIZE TABLE to reclaim space after deletions."""
    try:
        if dry_run:
            logger.info("[DRY-RUN] Would run OPTIMIZE TABLE syslogs FINAL")
            return

        # Note: OPTIMIZE TABLE is async, actual space reclaim may take time
        client.command("OPTIMIZE TABLE syslogs FINAL")
        logger.info("Scheduled OPTIMIZE TABLE syslogs FINAL")
    except Exception as e:
        logger.warning(f"Failed to optimize syslogs table: {e}")


def configure_system_table_ttl(client, dry_run: bool = False) -> None:
    """
    Configure TTL for system tables to auto-delete old entries.
    This prevents system tables from growing indefinitely.
    """
    # TTL settings: (table, ttl_expression, days)
    ttl_configs = [
        ('system.trace_log', 'event_date', 3),
        ('system.text_log', 'event_date', 3),
        ('system.query_log', 'event_date', 7),
        ('system.metric_log', 'event_date', 7),
        ('system.part_log', 'event_date', 7),
        ('system.asynchronous_metric_log', 'event_date', 3),
    ]

    for table, date_col, days in ttl_configs:
        try:
            if dry_run:
                logger.info(f"[DRY-RUN] Would set TTL on {table} to {days} days")
                continue

            query = f"ALTER TABLE {table} MODIFY TTL {date_col} + INTERVAL {days} DAY"
            client.command(query)
            logger.info(f"Set TTL on {table}: {days} days")
        except Exception as e:
            logger.debug(f"Could not set TTL on {table}: {e}")


def run_cleanup(
    threshold: float = 90.0,
    syslogs_retention_days: int = 60,
    dry_run: bool = False,
    force: bool = False
) -> Dict:
    """
    Main cleanup routine.

    Args:
        threshold: Disk usage percentage to trigger cleanup (default 90%)
        syslogs_retention_days: Days of syslogs to keep if aggressive cleanup needed
        dry_run: If True, only log what would be done
        force: If True, run cleanup regardless of disk usage

    Returns:
        Dict with cleanup results
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'initial_disk_usage': None,
        'final_disk_usage': None,
        'tables_truncated': [],
        'syslogs_deleted': 0,
        'cleanup_triggered': False,
        'success': True
    }

    # Check initial disk usage
    disk = get_disk_usage('/')
    results['initial_disk_usage'] = disk

    logger.info(f"Disk usage: {disk['usage_percent']:.1f}% ({disk['used_gb']:.1f}GB / {disk['total_gb']:.1f}GB)")

    if disk['usage_percent'] < threshold and not force:
        logger.info(f"Disk usage ({disk['usage_percent']:.1f}%) is below threshold ({threshold}%). No cleanup needed.")
        return results

    results['cleanup_triggered'] = True
    logger.warning(f"Disk usage ({disk['usage_percent']:.1f}%) exceeds threshold ({threshold}%). Starting cleanup...")

    try:
        client = get_clickhouse_client()

        # Step 1: Show current table sizes
        logger.info("Current ClickHouse table sizes:")
        tables = get_table_sizes(client)
        for t in tables[:10]:  # Top 10
            logger.info(f"  {t['database']}.{t['table']}: {t['size_readable']} ({t['total_rows']:,} rows)")

        # Step 2: Configure TTL on system tables (one-time, idempotent)
        logger.info("Configuring TTL on system tables...")
        configure_system_table_ttl(client, dry_run)

        # Step 3: Truncate system tables
        logger.info("Truncating system log tables...")
        for database, table in get_system_tables_to_clean():
            if truncate_table(client, database, table, dry_run):
                results['tables_truncated'].append(f"{database}.{table}")

        # Check disk usage again
        disk = get_disk_usage('/')
        logger.info(f"Disk usage after system table cleanup: {disk['usage_percent']:.1f}%")

        # Step 4: If still above threshold, delete old syslogs
        if disk['usage_percent'] >= threshold:
            logger.warning(f"Still above threshold. Deleting syslogs older than {syslogs_retention_days} days...")
            deleted = delete_old_syslogs(client, syslogs_retention_days, dry_run)
            results['syslogs_deleted'] = deleted

            # If still critical, try more aggressive retention
            if disk['usage_percent'] >= 95:
                logger.warning("Critical disk usage! Deleting syslogs older than 14 days...")
                deleted = delete_old_syslogs(client, 14, dry_run)
                results['syslogs_deleted'] += deleted

        # Step 5: Optimize table to reclaim space
        if results['tables_truncated'] or results['syslogs_deleted']:
            logger.info("Running table optimization...")
            optimize_tables(client, dry_run)

        # Final disk usage
        disk = get_disk_usage('/')
        results['final_disk_usage'] = disk
        logger.info(f"Final disk usage: {disk['usage_percent']:.1f}%")

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        results['success'] = False
        results['error'] = str(e)

    return results


def main():
    parser = argparse.ArgumentParser(
        description='ClickHouse disk cleanup utility',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=90.0,
        help='Disk usage percentage threshold to trigger cleanup'
    )
    parser.add_argument(
        '--retention', '-r',
        type=int,
        default=60,
        help='Days of syslogs to retain during cleanup'
    )
    parser.add_argument(
        '--dry-run', '-n',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force cleanup regardless of disk usage'
    )
    parser.add_argument(
        '--status', '-s',
        action='store_true',
        help='Only show disk and table status'
    )

    args = parser.parse_args()

    if args.status:
        disk = get_disk_usage('/')
        print(f"\nDisk Usage: {disk['usage_percent']:.1f}%")
        print(f"  Total: {disk['total_gb']:.1f} GB")
        print(f"  Used:  {disk['used_gb']:.1f} GB")
        print(f"  Free:  {disk['free_gb']:.1f} GB")

        try:
            client = get_clickhouse_client()
            tables = get_table_sizes(client)
            print("\nClickHouse Table Sizes:")
            for t in tables[:15]:
                print(f"  {t['database']}.{t['table']}: {t['size_readable']} ({t['total_rows']:,} rows)")
        except Exception as e:
            print(f"\nFailed to get ClickHouse stats: {e}")
        return

    results = run_cleanup(
        threshold=args.threshold,
        syslogs_retention_days=args.retention,
        dry_run=args.dry_run,
        force=args.force
    )

    # Print summary
    print("\n" + "=" * 50)
    print("CLEANUP SUMMARY")
    print("=" * 50)
    print(f"Timestamp: {results['timestamp']}")
    print(f"Cleanup triggered: {results['cleanup_triggered']}")
    print(f"Success: {results['success']}")

    if results['initial_disk_usage']:
        print(f"Initial disk usage: {results['initial_disk_usage']['usage_percent']:.1f}%")

    if results['final_disk_usage']:
        print(f"Final disk usage: {results['final_disk_usage']['usage_percent']:.1f}%")

    if results['tables_truncated']:
        print(f"Tables truncated: {len(results['tables_truncated'])}")
        for t in results['tables_truncated']:
            print(f"  - {t}")

    if results['syslogs_deleted']:
        print(f"Syslogs scheduled for deletion: ~{results['syslogs_deleted']:,}")

    if 'error' in results:
        print(f"Error: {results['error']}")

    # Exit with appropriate code
    sys.exit(0 if results['success'] else 1)


if __name__ == '__main__':
    main()
