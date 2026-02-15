"""
Address Object model for storing firewall address objects.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


class AddressObject(Base):
    """Address object for firewall policy generation."""

    __tablename__ = "address_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    obj_type: Mapped[str] = mapped_column(String(20), nullable=False)  # host, subnet, range, fqdn, group
    value: Mapped[str] = mapped_column(String(500), nullable=False)  # IP, CIDR, range, or FQDN
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # fortigate, paloalto, cisco, csv, manual
    members: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # For groups: comma-separated member names
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_ao_name", "name", unique=True),
        Index("idx_ao_type", "obj_type"),
        Index("idx_ao_value", "value"),
    )

    def __repr__(self) -> str:
        return f"<AddressObject {self.name} ({self.obj_type}: {self.value})>"
