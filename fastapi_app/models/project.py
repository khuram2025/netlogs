"""
Project and Communication Matrix models for managing network communication policies.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from ..db.database import Base


class ProjectStatus:
    """Project status constants."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ARCHIVED = "ARCHIVED"
    OTHER = "OTHER"

    CHOICES = [
        (ACTIVE, "Active"),
        (INACTIVE, "Inactive"),
        (ARCHIVED, "Archived"),
        (OTHER, "Other"),
    ]


class Project(Base):
    """Project model for organizing communication matrices."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    resources: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default=ProjectStatus.OTHER, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship to communication matrix entries
    communication_entries: Mapped[List["CommunicationMatrixEntry"]] = relationship(
        "CommunicationMatrixEntry",
        back_populates="project",
        cascade="all, delete-orphan",
        lazy="selectin"
    )

    __table_args__ = (
        Index("idx_project_name", "name"),
        Index("idx_project_status", "status"),
        Index("idx_project_owner", "owner"),
    )

    def __repr__(self) -> str:
        return f"<Project {self.name} ({self.status})>"

    @property
    def status_display(self) -> str:
        """Return human-readable status."""
        for value, display in ProjectStatus.CHOICES:
            if value == self.status:
                return display
        return self.status

    @property
    def entry_count(self) -> int:
        """Return number of communication matrix entries."""
        return len(self.communication_entries) if self.communication_entries else 0


class ConnectionType:
    """Connection type constants."""
    PERMANENT = "PERMANENT"
    TEMPORARY = "TEMPORARY"

    CHOICES = [
        (PERMANENT, "Permanent"),
        (TEMPORARY, "Temporary"),
    ]


class CommunicationMatrixEntry(Base):
    """Communication Matrix Entry for tracking network communication rules."""

    __tablename__ = "communication_matrix_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )

    # Source information
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Destination information
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    destination_port: Mapped[str] = mapped_column(String(100), nullable=False)

    # Protocol (TCP/UDP/ICMP/ANY)
    protocol: Mapped[str] = mapped_column(String(20), default="TCP", nullable=False)

    # Connection type
    connection_type: Mapped[str] = mapped_column(
        String(20), default=ConnectionType.PERMANENT, nullable=False
    )

    # Additional fields
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship back to project
    project: Mapped["Project"] = relationship("Project", back_populates="communication_entries")

    __table_args__ = (
        Index("idx_comm_project", "project_id"),
        Index("idx_comm_source_ip", "source_ip"),
        Index("idx_comm_dest_ip", "destination_ip"),
        Index("idx_comm_dest_port", "destination_port"),
        Index("idx_comm_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<CommunicationMatrixEntry {self.source_ip} -> {self.destination_ip}:{self.destination_port}>"

    @property
    def connection_type_display(self) -> str:
        """Return human-readable connection type."""
        for value, display in ConnectionType.CHOICES:
            if value == self.connection_type:
                return display
        return self.connection_type
