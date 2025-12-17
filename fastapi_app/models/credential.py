"""
DeviceCredential model - SSH credentials for device management.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from cryptography.fernet import Fernet
import base64
import os
import logging

from ..db.database import Base

logger = logging.getLogger(__name__)

# Key file path - stored in app directory for persistence
_KEY_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.credential_key')

# Encryption key - cached after first load
_ENCRYPTION_KEY = None


def _load_or_create_key() -> str:
    """
    Load encryption key from environment variable or key file.
    If neither exists, generate a new key and save it to the key file.
    This ensures the key persists across application restarts.
    """
    # Priority 1: Environment variable (most secure for production)
    env_key = os.environ.get('CREDENTIAL_ENCRYPTION_KEY')
    if env_key:
        logger.info("Using encryption key from CREDENTIAL_ENCRYPTION_KEY environment variable")
        return env_key

    # Priority 2: Key file (for development/persistence without env var)
    if os.path.exists(_KEY_FILE_PATH):
        try:
            with open(_KEY_FILE_PATH, 'r') as f:
                key = f.read().strip()
                if key:
                    logger.info(f"Loaded encryption key from {_KEY_FILE_PATH}")
                    return key
        except Exception as e:
            logger.warning(f"Failed to read key file: {e}")

    # Priority 3: Generate new key and save to file
    logger.warning(
        "No CREDENTIAL_ENCRYPTION_KEY environment variable set. "
        f"Generating new key and saving to {_KEY_FILE_PATH}. "
        "For production, set CREDENTIAL_ENCRYPTION_KEY environment variable."
    )
    new_key = Fernet.generate_key().decode()
    try:
        with open(_KEY_FILE_PATH, 'w') as f:
            f.write(new_key)
        # Set restrictive permissions (owner read/write only)
        os.chmod(_KEY_FILE_PATH, 0o600)
        logger.info(f"Generated and saved new encryption key to {_KEY_FILE_PATH}")
    except Exception as e:
        logger.error(f"Failed to save key file: {e}. Key will not persist across restarts!")

    return new_key


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
    return Fernet(key)


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
