"""URL SiteClean rule model — noise filtering rules for URL/webfilter logs."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from ..db.database import Base


class URLCleanRule(Base):
    __tablename__ = "url_clean_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_type = Column(String(30), nullable=False)      # hostname_exact, hostname_glob, category, url_contains
    pattern = Column(String(500), nullable=False)
    label = Column(String(200), nullable=False)
    group_name = Column(String(100), default="General")
    enabled = Column(Boolean, default=True)
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<URLCleanRule {self.label} ({self.rule_type}: {self.pattern})>"
