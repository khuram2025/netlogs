"""
Database connection management for PostgreSQL using async SQLAlchemy.
"""

import logging
from typing import AsyncGenerator, Optional
from urllib.parse import quote_plus
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker, AsyncEngine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from ..core.config import settings

logger = logging.getLogger(__name__)


def get_database_url() -> str:
    """Build database URL - use 127.0.0.1 instead of localhost for asyncpg compatibility."""
    db_host = settings.postgres_host
    if db_host == "localhost":
        db_host = "127.0.0.1"
    # URL-encode password to handle special characters
    encoded_password = quote_plus(settings.postgres_password)
    return f"postgresql+asyncpg://{settings.postgres_user}:{encoded_password}@{db_host}:{settings.postgres_port}/{settings.postgres_db}"


# Create async engine
engine = create_async_engine(
    get_database_url(),
    echo=settings.debug,
    poolclass=NullPool,
)

# Session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a database session."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    # Ensure models are imported so `Base.metadata` is fully populated.
    # Without this, new tables (e.g., settings tables) may not be created.
    from ..models import device  # noqa: F401
    from ..models import credential  # noqa: F401
    from ..models import routing  # noqa: F401
    from ..models import device_ssh_settings  # noqa: F401
    from ..models import zone  # noqa: F401
    from ..models import project  # noqa: F401
    from ..models import edl  # noqa: F401
    from ..models import storage_settings  # noqa: F401
    from ..models import user  # noqa: F401
    from ..models import alert  # noqa: F401
    from ..models import api_key  # noqa: F401
    from ..models import threat_intel  # noqa: F401
    from ..models import correlation  # noqa: F401
    from ..models import saved_search  # noqa: F401
    from ..models import dashboard  # noqa: F401
    from ..models import address_object  # noqa: F401
    from ..models import system_settings  # noqa: F401
    from ..models import llm_config  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create default admin user if no users exist
    await _create_default_admin()

    # Seed pre-built alert rules on first run
    await _seed_alert_rules()


async def _create_default_admin() -> None:
    """Create the default admin user on first run."""
    from ..models.user import User, UserRole

    async with async_session_maker() as session:
        try:
            result = await session.execute(
                select(User).where(User.username == "admin").limit(1)
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                admin = User(
                    username="admin",
                    email="admin@netlogs.local",
                    role=UserRole.ADMIN.value,
                    is_active=True,
                )
                admin.set_password("changeme")
                session.add(admin)
                await session.commit()
                logger.info("Default admin user created (admin/changeme)")
            else:
                logger.debug("Admin user already exists, skipping creation")
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to create default admin user: {e}")


async def _seed_alert_rules() -> None:
    """Seed pre-built alert rules on first run."""
    from ..models.alert import AlertRule
    from sqlalchemy import func

    async with async_session_maker() as session:
        try:
            # Get existing rule names to avoid duplicates
            existing_result = await session.execute(select(AlertRule.name))
            existing_names = {row[0] for row in existing_result.all()}

            all_rules = [
                AlertRule(
                    name="Brute Force Detection",
                    description="Detects >20 denied connections from same source IP to same destination port within 5 minutes",
                    severity="high",
                    category="brute_force",
                    condition_type="pattern",
                    condition_config={
                        "rules": [
                            {"field": "action", "value": "deny|drop|block|reject"},
                        ],
                        "threshold": 20,
                        "window_minutes": 5,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=15,
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Port Scan Detection",
                    description="Detects >10 different destination ports from same source IP within 2 minutes",
                    severity="high",
                    category="port_scan",
                    condition_type="threshold",
                    condition_config={
                        "field": "action",
                        "value": "deny|drop|block|reject",
                        "threshold": 10,
                        "window_minutes": 2,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=10,
                    mitre_tactic="Discovery",
                    mitre_technique="T1046",
                    is_enabled=True,
                ),
                AlertRule(
                    name="DDoS Indicator",
                    description="Detects >1000 connections from same source IP within 1 minute",
                    severity="critical",
                    category="ddos",
                    condition_type="threshold",
                    condition_config={
                        "field": "srcip",
                        "value": "",
                        "threshold": 1000,
                        "window_minutes": 1,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=5,
                    mitre_tactic="Impact",
                    mitre_technique="T1498",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Device Offline",
                    description="Triggers when no logs received from an approved device for 10 minutes",
                    severity="medium",
                    category="absence",
                    condition_type="absence",
                    condition_config={
                        "device_ip": "",
                        "timeout_minutes": 10,
                    },
                    cooldown_minutes=30,
                    mitre_tactic="Impact",
                    mitre_technique="T1489",
                    is_enabled=False,  # Disabled by default - needs device_ip configured
                ),
                AlertRule(
                    name="High Deny Rate",
                    description="Detects >50% denied traffic exceeding 500 events from a source within 15 minutes",
                    severity="medium",
                    category="threshold",
                    condition_type="threshold",
                    condition_config={
                        "field": "action",
                        "value": "deny|drop|block|reject",
                        "threshold": 500,
                        "window_minutes": 15,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=30,
                    mitre_tactic="Impact",
                    mitre_technique="T1499",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Critical Severity Spike",
                    description="Detects >10 critical severity (0-2) log entries within 5 minutes",
                    severity="high",
                    category="threshold",
                    condition_type="threshold",
                    condition_config={
                        "field": "severity",
                        "value": "0",
                        "threshold": 10,
                        "window_minutes": 5,
                    },
                    cooldown_minutes=15,
                    mitre_tactic="Impact",
                    mitre_technique="T1499.004",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Admin Port Access Denied",
                    description="Detects denied traffic to admin ports (22, 3389, 8443) from external IPs",
                    severity="medium",
                    category="port_scan",
                    condition_type="pattern",
                    condition_config={
                        "rules": [
                            {"field": "action", "value": "deny|drop|block|reject"},
                            {"field": "dstport", "value": "22"},
                        ],
                        "threshold": 5,
                        "window_minutes": 5,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=15,
                    mitre_tactic="Initial Access",
                    mitre_technique="T1133",
                    is_enabled=True,
                ),
                AlertRule(
                    name="DNS Tunneling Suspect",
                    description="Detects >100 DNS queries (port 53) from a single IP within 5 minutes",
                    severity="medium",
                    category="exfiltration",
                    condition_type="pattern",
                    condition_config={
                        "rules": [
                            {"field": "dstport", "value": "53"},
                        ],
                        "threshold": 100,
                        "window_minutes": 5,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=30,
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071.004",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Data Exfiltration Suspect",
                    description="Detects high volume outbound traffic - >5000 events from single IP within 60 minutes",
                    severity="high",
                    category="exfiltration",
                    condition_type="threshold",
                    condition_config={
                        "field": "action",
                        "value": "accept|allow|pass|close",
                        "threshold": 5000,
                        "window_minutes": 60,
                        "group_by": "srcip",
                    },
                    cooldown_minutes=60,
                    mitre_tactic="Exfiltration",
                    mitre_technique="T1048",
                    is_enabled=True,
                ),
                AlertRule(
                    name="Anomalous Traffic Spike",
                    description="Triggers when current event rate exceeds 3x the 24-hour baseline average",
                    severity="medium",
                    category="anomaly",
                    condition_type="anomaly",
                    condition_config={
                        "metric": "eps",
                        "multiplier": 3,
                        "window_minutes": 5,
                        "baseline_hours": 24,
                    },
                    cooldown_minutes=30,
                    mitre_tactic="Impact",
                    mitre_technique="T1498",
                    is_enabled=True,
                ),
            ]

            new_rules = [r for r in all_rules if r.name not in existing_names]
            if not new_rules:
                logger.debug("All pre-built alert rules already exist")
                return

            for rule in new_rules:
                session.add(rule)

            await session.commit()
            logger.info(f"Seeded {len(new_rules)} new pre-built alert rules ({len(existing_names)} already existed)")

        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to seed alert rules: {e}")


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()
