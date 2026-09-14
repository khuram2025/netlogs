"""
ComplianceAttestation — manual reviewer attestations per (device, framework,
control).

Used alongside the auto-evaluated analytics findings in the PDF report:
controls that can't be proven from config alone (e.g. quarterly log review,
physical access checks) still need a human to tick them off. Storing the
reviewer + timestamp + notes gives auditors a paper trail.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String, Integer, DateTime, ForeignKey, Text, Index, UniqueConstraint,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from ..db.database import Base


# Status values accepted in the `status` column. Mirrors what the report
# template renders — anything else would break the pill styling.
ATTESTATION_STATUSES = ("pass", "partial", "fail", "na")


class ComplianceAttestation(Base):
    """A manual override of a single compliance control's status.

    Uniqueness is per ``(device_id, framework, control_id)``. The framework
    slug is one of ``nca_ecc``, ``pci_dss``, ``iso_27001``, ``cis_v8``
    (matching the keys in ``_compute_compliance_findings``).
    """

    __tablename__ = "compliance_attestations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    framework:  Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Status is nullable so a row can exist only to carry the
    # ``include_in_report`` flag (a control excluded from the report
    # doesn't need a manual status — the PDF simply skips it).
    status:     Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    include_in_report: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true", default=True,
    )
    notes:      Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Proof upload ──────────────────────────────────────────
    # Optional screenshot / scanned evidence attached by the reviewer.
    # One file per attestation (overwritten on re-upload). The file is
    # served from the app's static proofs directory, and embedded as a
    # base64 data URL inside the PDF so reports stay self-contained.
    proof_path:     Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    proof_filename: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    proof_mimetype: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    proof_size:     Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("device_id", "framework", "control_id",
                         name="uq_attestation_device_framework_control"),
        Index("idx_attestation_device", "device_id"),
        Index("idx_attestation_framework", "device_id", "framework"),
    )

    def __repr__(self) -> str:
        return (f"<ComplianceAttestation dev:{self.device_id} "
                f"{self.framework}/{self.control_id} {self.status}>")
