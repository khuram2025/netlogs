"""
Correlation Rule models for multi-stage event correlation.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON, Float, Index,
)
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

    # Phase 1: rule version (bumped on each update; recorded in every match
    # so a match can be tied to the exact rule definition that produced it).
    version = Column(Integer, nullable=False, default=1, server_default="1")

    # Phase 1: match mode controls how repeated detections are recorded.
    #   "discrete"  — one record per (rule, entity) per suppress_window
    #                 (a real attack chain; suppress scheduler-tick repeats)
    #   "recurring" — record every evaluation while the condition holds
    #                 (an intentional continuous monitor)
    match_mode = Column(String(20), nullable=False,
                        default="discrete", server_default="discrete")

    # Phase 1: suppression window in seconds. Within this window a discrete
    # rule records a given (rule, entity) chain at most once.
    suppress_window = Column(Integer, nullable=False,
                             default=3600, server_default="3600")

    # Phase 2: stage ordering.
    #   "sequence"  — stage N must occur *after* stage N-1 in event time,
    #                 for the same entity, within stage N's window
    #   "any_order" — legacy: each stage is an independent trailing window
    ordering = Column(String(20), nullable=False,
                      default="sequence", server_default="sequence")

    # Phase 2: stage-JSON shape marker (2 = Phase 2).
    schema_version = Column(Integer, nullable=False,
                            default=2, server_default="2")

    # Phase 2: columns that link stages into one chain, e.g. ["srcip"] or
    # ["srcip", "dstip"]. NULL falls back to stage 1's group_by.
    join_keys = Column(JSON, nullable=True)

    # Phase 5: risk points a match of this rule adds to the implicated
    # entity. 0 = auto-derive from severity.
    risk_score = Column(Integer, nullable=False, default=0, server_default="0")

    # Phase 6: response actions fired when this rule records a match —
    # a JSON list, e.g. [{"type": "webhook", "url": "..."},
    # {"type": "log", "level": "warning"}].
    actions = Column(JSON, nullable=True)

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


class CorrelationIncident(Base):
    """Phase 5: a correlation incident — related matches for one entity,
    grouped so analysts triage a prioritized incident instead of a flat
    alert stream."""
    __tablename__ = "correlation_incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # The entity the incident is about.
    entity_type = Column(String(40), nullable=False, default="ip")
    entity_value = Column(String(255), nullable=False, index=True)

    # Lifecycle: new -> investigating -> contained -> resolved (or suppressed).
    status = Column(String(20), nullable=False, default="new", index=True)

    # Severity derived from accumulated risk + contributing rule severities.
    severity = Column(String(20), nullable=False, default="medium")

    # Accumulated, time-decayed risk score for the entity at last update.
    risk_score = Column(Float, nullable=False, default=0.0)

    # How many correlation matches rolled into this incident.
    match_count = Column(Integer, nullable=False, default=0)

    # Distinct contributing rule names / MITRE tactics (JSON lists).
    rule_names = Column(JSON, nullable=True)
    mitre_tactics = Column(JSON, nullable=True)

    # Evidence — a capped list of match summaries (newest first).
    matches = Column(JSON, nullable=True)

    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_corr_incident_status", "status"),
        Index("ix_corr_incident_entity", "entity_value"),
    )
