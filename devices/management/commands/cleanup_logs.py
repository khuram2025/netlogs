"""
Management command to clean up old logs based on per-device retention settings.

Usage:
    python manage.py cleanup_logs           # Dry-run mode (shows what would be deleted)
    python manage.py cleanup_logs --execute # Actually delete the logs
    python manage.py cleanup_logs --device 192.168.1.1 --execute  # Clean specific device

This command should be run periodically via cron or systemd timer:
    0 2 * * * cd /home/net/net-logs && /home/net/net-logs/venv/bin/python manage.py cleanup_logs --execute
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from devices.models import Device
from logs.clickhouse_client import ClickHouseClient
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old logs based on per-device retention settings'

    def add_arguments(self, parser):
        parser.add_argument(
            '--execute',
            action='store_true',
            help='Actually execute the deletion. Without this flag, runs in dry-run mode.',
        )
        parser.add_argument(
            '--device',
            type=str,
            help='Only clean up logs for a specific device IP address.',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show verbose output.',
        )

    def handle(self, *args, **options):
        execute = options['execute']
        specific_device = options.get('device')
        verbose = options['verbose']

        if not execute:
            self.stdout.write(self.style.WARNING(
                'Running in DRY-RUN mode. Use --execute to actually delete logs.\n'
            ))

        # Get devices with retention policies
        if specific_device:
            devices = Device.objects.filter(ip_address=specific_device)
            if not devices.exists():
                self.stdout.write(self.style.ERROR(f'Device {specific_device} not found.'))
                return
        else:
            # Only get devices that have retention enabled (retention_days > 0)
            devices = Device.objects.filter(retention_days__gt=0, status='APPROVED')

        if not devices.exists():
            self.stdout.write(self.style.SUCCESS('No devices with retention policies to process.'))
            return

        self.stdout.write(f'Processing {devices.count()} device(s)...\n')

        total_cleaned = 0
        errors = []

        for device in devices:
            device_ip = str(device.ip_address)
            retention_days = device.retention_days

            if retention_days == 0:
                if verbose:
                    self.stdout.write(f'  {device_ip}: Unlimited retention, skipping.')
                continue

            if verbose:
                self.stdout.write(f'  {device_ip}: Retention = {retention_days} days')

            # Get current log age distribution to show what would be affected
            try:
                age_dist = ClickHouseClient.get_device_log_age_distribution(device_ip)
                logs_to_delete = 0

                # Calculate how many logs would be deleted based on retention
                if retention_days <= 1:
                    logs_to_delete = age_dist['last_week'] + age_dist['last_month'] + age_dist['older']
                elif retention_days <= 7:
                    logs_to_delete = age_dist['last_month'] + age_dist['older']
                elif retention_days <= 30:
                    logs_to_delete = age_dist['older']
                else:
                    # For longer retention periods, we need a more precise query
                    logs_to_delete = age_dist['older']  # Approximate

                if verbose or logs_to_delete > 0:
                    self.stdout.write(
                        f'    Total logs: {age_dist["total"]:,}, '
                        f'Logs to delete (approx): {logs_to_delete:,}'
                    )

                if execute and logs_to_delete > 0:
                    success = ClickHouseClient.delete_old_logs_for_device(device_ip, retention_days)
                    if success:
                        self.stdout.write(self.style.SUCCESS(
                            f'    Scheduled deletion for {device_ip}'
                        ))
                        total_cleaned += 1
                    else:
                        errors.append(device_ip)
                        self.stdout.write(self.style.ERROR(
                            f'    Failed to delete logs for {device_ip}'
                        ))

            except Exception as e:
                errors.append(device_ip)
                self.stdout.write(self.style.ERROR(f'    Error processing {device_ip}: {e}'))
                logger.exception(f'Error processing device {device_ip}')

        # Summary
        self.stdout.write('\n' + '=' * 50)
        if execute:
            self.stdout.write(self.style.SUCCESS(
                f'Cleanup completed. Scheduled deletion for {total_cleaned} device(s).'
            ))
            if errors:
                self.stdout.write(self.style.ERROR(
                    f'Errors occurred for: {", ".join(errors)}'
                ))
            self.stdout.write(self.style.NOTICE(
                '\nNote: ClickHouse mutations are async. Use system.mutations to monitor progress.'
            ))
        else:
            self.stdout.write(self.style.WARNING(
                'DRY-RUN completed. No logs were deleted.\n'
                'Run with --execute to actually delete logs.'
            ))
