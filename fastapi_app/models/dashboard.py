"""
Custom Dashboard models for user-configurable dashboards with widgets.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Index
from ..db.database import Base


class CustomDashboard(Base):
    """A user-created custom dashboard with configurable widgets."""
    __tablename__ = "custom_dashboards"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    is_shared = Column(Boolean, default=False)
    is_default = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_dashboard_user", "user_id"),
    )


class DashboardWidget(Base):
    """A widget within a custom dashboard."""
    __tablename__ = "dashboard_widgets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dashboard_id = Column(Integer, ForeignKey("custom_dashboards.id", ondelete="CASCADE"), nullable=False)

    widget_type = Column(String(50), nullable=False)  # counter, line_chart, bar_chart, doughnut, table, gauge
    title = Column(String(200), nullable=False)

    # Widget configuration
    config = Column(JSON, nullable=False)
    # {
    #   "data_source": "logs",          -- logs, alerts, ioc_matches, correlation_matches
    #   "query": {"action": "deny"},    -- filter conditions
    #   "aggregation": "count",         -- count, sum, avg, max, min, unique
    #   "group_by": "srcip",            -- field to group by (for charts)
    #   "time_range": "24h",            -- time range
    #   "limit": 10,                    -- max items for top-N charts
    #   "refresh_seconds": 60,          -- auto-refresh interval
    # }

    # Grid position (12-column grid)
    position_x = Column(Integer, default=0)
    position_y = Column(Integer, default=0)
    width = Column(Integer, default=6)   # Grid columns (out of 12)
    height = Column(Integer, default=4)  # Grid rows

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_widget_dashboard", "dashboard_id"),
    )
