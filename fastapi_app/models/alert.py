"""
Alert models for the alerting engine.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.orm import relationship

from ..db.database import Base


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    category = Column(String(50), nullable=True)  # brute_force, port_scan, anomaly, threshold, absence

    is_enabled = Column(Boolean, default=True)

    # Conditions
    condition_type = Column(String(30), nullable=False)  # threshold, pattern, anomaly, absence
    condition_config = Column(JSON, nullable=False)

    # Cooldown
    cooldown_minutes = Column(Integer, default=15)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)

    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)

    # Metadata
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    alerts = relationship("Alert", back_populates="rule", cascade="all, delete-orphan")
    notification_mappings = relationship("AlertRuleNotification", back_populates="rule", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id"), nullable=True)
    severity = Column(String(20), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)  # Matching log data, counts, etc.

    status = Column(String(20), default="new")  # new, acknowledged, investigating, resolved, false_positive
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    triggered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    rule = relationship("AlertRule", back_populates="alerts")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    channel_type = Column(String(30), nullable=False)  # email, telegram, webhook
    config = Column(JSON, nullable=False)
    is_enabled = Column(Boolean, default=True)
    last_sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    rule_mappings = relationship("AlertRuleNotification", back_populates="channel", cascade="all, delete-orphan")


class AlertRuleNotification(Base):
    __tablename__ = "alert_rule_notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False)
    channel_id = Column(Integer, ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False)

    __table_args__ = (
        UniqueConstraint('rule_id', 'channel_id', name='uq_rule_channel'),
    )

    # Relationships
    rule = relationship("AlertRule", back_populates="notification_mappings")
    channel = relationship("NotificationChannel", back_populates="rule_mappings")
