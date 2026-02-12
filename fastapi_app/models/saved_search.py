"""
Saved Search model for storing and reusing log search queries.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Index
from ..db.database import Base


class SavedSearch(Base):
    """A saved log search query that can be named, shared, and reused."""
    __tablename__ = "saved_searches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # All filter parameters stored as JSON
    query_params = Column(JSON, nullable=False)
    # Stores: q, device, severity, action, srcip, dstip, srcport, dstport,
    #         protocol, application, policyname, log_type, threat_id,
    #         session_end_reason, src_zone, dst_zone, time_range, per_page

    is_shared = Column(Boolean, default=False)

    # Usage tracking
    use_count = Column(Integer, default=0)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_saved_search_user", "user_id"),
        Index("ix_saved_search_shared", "is_shared"),
    )
