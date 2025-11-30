from django.db import models
from django.utils import timezone
from datetime import timedelta

class Device(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    PARSER_CHOICES = [
        ('GENERIC', 'Generic Syslog'),
        ('FORTINET', 'Fortinet'),
        ('PALOALTO', 'Palo Alto'),
    ]

    RETENTION_CHOICES = [
        (7, '7 days'),
        (14, '14 days'),
        (30, '30 days'),
        (60, '60 days'),
        (90, '90 days (default)'),
        (180, '180 days'),
        (365, '1 year'),
        (0, 'Forever (no auto-delete)'),
    ]

    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    parser = models.CharField(max_length=50, choices=PARSER_CHOICES, default='GENERIC')
    device_type = models.CharField(max_length=100, blank=True, null=True)
    retention_days = models.PositiveIntegerField(
        default=90,
        choices=RETENTION_CHOICES,
        help_text='Number of days to retain logs for this device. Set to 0 for unlimited retention.'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_log_received = models.DateTimeField(blank=True, null=True)
    log_count = models.PositiveBigIntegerField(default=0)

    def __str__(self):
        return f"{self.ip_address} ({self.status})"

    @property
    def is_stale(self):
        """Returns True if no logs received in the last 5 minutes."""
        if not self.last_log_received:
            return False
        return timezone.now() - self.last_log_received > timedelta(minutes=5)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status'], name='idx_device_status'),
            models.Index(fields=['ip_address'], name='idx_device_ip'),
            models.Index(fields=['last_log_received'], name='idx_device_last_log'),
            models.Index(fields=['status', 'parser'], name='idx_device_status_parser'),
        ]
