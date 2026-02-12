"""
Storage Settings model - Configuration for automatic storage management.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, BigInteger, DateTime, Float, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class StorageSettings(Base):
    """
    Storage settings for automatic log management and cleanup.

    This model stores configuration for:
    - Maximum storage quota for syslogs
    - Auto-cleanup thresholds and behaviors
    - Cleanup history and status
    """

    __tablename__ = "storage_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Storage quota settings (in bytes)
    syslogs_max_size_gb: Mapped[float] = mapped_column(Float, default=600.0, nullable=False)

    # Cleanup behavior settings
    auto_cleanup_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cleanup_trigger_percent: Mapped[float] = mapped_column(Float, default=95.0, nullable=False)  # Trigger at 95% of quota
    cleanup_target_percent: Mapped[float] = mapped_column(Float, default=80.0, nullable=False)   # Clean down to 80% of quota
    min_retention_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)          # Never delete logs newer than 7 days

    # Disk-based thresholds (additional safety)
    disk_warning_percent: Mapped[float] = mapped_column(Float, default=85.0, nullable=False)
    disk_critical_percent: Mapped[float] = mapped_column(Float, default=95.0, nullable=False)

    # Monitor interval (in minutes)
    monitor_interval_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)

    # Last cleanup tracking
    last_cleanup_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_cleanup_freed_gb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_cleanup_rows_deleted: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_cleanup_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # success, failed, partial
    last_cleanup_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Current monitoring status
    current_size_gb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    current_rows: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_monitored_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<StorageSettings max={self.syslogs_max_size_gb}GB, auto={self.auto_cleanup_enabled}>"

    @property
    def max_size_bytes(self) -> int:
        """Return max size in bytes."""
        return int(self.syslogs_max_size_gb * 1024 * 1024 * 1024)

    @property
    def trigger_size_bytes(self) -> int:
        """Return cleanup trigger threshold in bytes."""
        return int(self.max_size_bytes * (self.cleanup_trigger_percent / 100))

    @property
    def target_size_bytes(self) -> int:
        """Return cleanup target size in bytes."""
        return int(self.max_size_bytes * (self.cleanup_target_percent / 100))

    @property
    def needs_cleanup(self) -> bool:
        """Check if cleanup is needed based on current size."""
        if self.current_size_gb is None:
            return False
        current_bytes = self.current_size_gb * 1024 * 1024 * 1024
        return current_bytes >= self.trigger_size_bytes

    @property
    def usage_percent(self) -> float:
        """Calculate current usage as percentage of quota."""
        if self.current_size_gb is None or self.syslogs_max_size_gb <= 0:
            return 0.0
        return round((self.current_size_gb / self.syslogs_max_size_gb) * 100, 1)


class StorageCleanupLog(Base):
    """
    Log of storage cleanup operations for auditing and troubleshooting.
    """

    __tablename__ = "storage_cleanup_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Cleanup details
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False)  # scheduled, manual, emergency
    trigger_reason: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "quota exceeded: 615GB > 600GB"

    # Before/after metrics
    size_before_gb: Mapped[float] = mapped_column(Float, nullable=False)
    size_after_gb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    rows_before: Mapped[int] = mapped_column(BigInteger, nullable=False)
    rows_after: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Operation details
    deleted_before_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deletion_query: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status and timing
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # started, success, failed, partial
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    def __repr__(self) -> str:
        return f"<StorageCleanupLog {self.id} {self.status} {self.started_at}>"
