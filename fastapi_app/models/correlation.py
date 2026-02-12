"""
Correlation Rule models for multi-stage event correlation.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, Index
from ..db.database import Base


class CorrelationRule(Base):
    """Multi-stage correlation rule for detecting complex attack patterns."""
    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="high")
    is_enabled = Column(Boolean, default=True, index=True)

    # Rule stages (ordered conditions as JSON array)
    # Each stage: {"name": str, "filter": dict, "threshold": int, "window": int (seconds), "group_by": str}
    stages = Column(JSON, nullable=False)

    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)

    # Evaluation tracking
    last_evaluated_at = Column(DateTime(timezone=True), nullable=True)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    trigger_count = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_corr_rule_enabled", "is_enabled"),
    )
