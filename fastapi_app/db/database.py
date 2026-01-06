"""
Database connection management for PostgreSQL using async SQLAlchemy.
"""

import logging
from typing import AsyncGenerator, Optional
from urllib.parse import quote_plus
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

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()
