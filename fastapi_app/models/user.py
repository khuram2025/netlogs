"""
User model for authentication and authorization.
"""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum as SAEnum
from passlib.context import CryptContext

from ..db.database import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"

    CHOICES = [
        ("ADMIN", "Admin - Full access"),
        ("ANALYST", "Analyst - Operational access"),
        ("VIEWER", "Viewer - Read-only access"),
    ]


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.VIEWER.value)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def set_password(self, password: str):
        """Hash and set the password."""
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        return pwd_context.verify(password, self.password_hash)

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        now = datetime.now(timezone.utc)
        if self.locked_until.tzinfo is None:
            return self.locked_until > now.replace(tzinfo=None)
        return self.locked_until > now

    @property
    def role_display(self) -> str:
        return self.role.title() if self.role else "Viewer"

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
