"""
API Key model for programmatic access.
"""

import secrets
import hashlib
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON

from ..db.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False)
    key_prefix = Column(String(8), nullable=False)  # First 8 chars for identification
    permissions = Column(JSON, default=["read"])
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    @staticmethod
    def generate_key() -> str:
        """Generate a secure API key (32 bytes = 64 hex chars)."""
        return "nlk_" + secrets.token_hex(32)

    @staticmethod
    def hash_key(key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    @property
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False
        now = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is None:
            return self.expires_at < now.replace(tzinfo=None)
        return self.expires_at < now
