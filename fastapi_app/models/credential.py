"""
DeviceCredential model - SSH credentials for device management.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from cryptography.fernet import Fernet, MultiFernet
import base64
import os
import logging

from ..db.database import Base

logger = logging.getLogger(__name__)

# Appliance keys live in the persistent credentials volume, never in source/images.
from pathlib import Path
_KEY_FILE_PATH = os.environ.get('CREDENTIAL_KEY_FILE', '/app/data/credentials/device-credentials.key')
_LEGACY_KEY_FILE = Path(_KEY_FILE_PATH).with_name('legacy-device-credentials.key')
_ENCRYPTION_KEY = None


def _load_or_create_key() -> str:
    env_key = os.environ.get('CREDENTIAL_ENCRYPTION_KEY')
    if env_key:
        return env_key
    path = Path(_KEY_FILE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    with os.fdopen(fd, 'w') as stream:
        stream.write(Fernet.generate_key().decode()); stream.flush(); os.fsync(stream.fileno())
    return path.read_text().strip()


async def rotate_legacy_credentials(session_factory):
    if not _LEGACY_KEY_FILE.exists():
        return
    from sqlalchemy import select
    new = Fernet(_load_or_create_key().encode())
    old = Fernet(_LEGACY_KEY_FILE.read_bytes().strip())
    combined = MultiFernet([new, old])
    async with session_factory() as session:
        rows = (await session.execute(select(DeviceCredential))).scalars().all()
        for row in rows:
            row._password = new.encrypt(combined.decrypt(row._password.encode())).decode()
        await session.commit()
    _LEGACY_KEY_FILE.unlink()
    logger.info('Legacy device credentials migrated to a persistent appliance-specific key')


def get_cipher():
    """Get encryption cipher with persistent key."""
    global _ENCRYPTION_KEY
    if _ENCRYPTION_KEY is None:
        _ENCRYPTION_KEY = _load_or_create_key()

    key = _ENCRYPTION_KEY.encode() if isinstance(_ENCRYPTION_KEY, str) else _ENCRYPTION_KEY
    # Ensure key is valid Fernet key (32 bytes base64-encoded = 44 chars)
    if len(key) != 44:
        # Generate a consistent key from the provided value using SHA-256
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    return MultiFernet([Fernet(key), Fernet(_LEGACY_KEY_FILE.read_bytes().strip())]) if _LEGACY_KEY_FILE.exists() else Fernet(key)


class CredentialType:
    """Credential type constants."""
    SSH = "SSH"
    API = "API"
    SNMP = "SNMP"

    CHOICES = [
        (SSH, "SSH"),
        (API, "API Key"),
        (SNMP, "SNMP Community"),
    ]


class DeviceCredential(Base):
    """Device credentials for SSH/API access."""

    __tablename__ = "device_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    credential_type: Mapped[str] = mapped_column(
        String(20), default=CredentialType.SSH, nullable=False
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    _password: Mapped[str] = mapped_column("password", Text, nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_used: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_credential_device", "device_id"),
        Index("idx_credential_type", "credential_type"),
        Index("idx_credential_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<DeviceCredential {self.username}@device:{self.device_id}>"

    @property
    def password(self) -> str:
        """Decrypt and return password."""
        try:
            cipher = get_cipher()
            return cipher.decrypt(self._password.encode()).decode()
        except Exception:
            # If decryption fails, return placeholder (don't expose encrypted value)
            return "[Decryption failed - please re-enter password]"

    @password.setter
    def password(self, value: str):
        """Encrypt and store password."""
        cipher = get_cipher()
        self._password = cipher.encrypt(value.encode()).decode()

    @property
    def credential_type_display(self) -> str:
        """Return human-readable credential type."""
        for value, display in CredentialType.CHOICES:
            if value == self.credential_type:
                return display
        return self.credential_type

    @property
    def masked_password(self) -> str:
        """Return masked password for display."""
        return "••••••••"


class DeviceVdom(Base):
    """Virtual Domain (VDOM) configuration for Fortinet devices."""

    __tablename__ = "device_vdoms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices_device.id", ondelete="CASCADE"), nullable=False
    )
    vdom_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_vdom_device", "device_id"),
        Index("idx_vdom_name", "vdom_name"),
        Index("idx_vdom_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<DeviceVdom {self.vdom_name}@device:{self.device_id}>"
