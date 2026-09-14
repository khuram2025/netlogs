"""
PostgreSQL migration helper - runs Alembic migrations programmatically on app startup.
For existing databases: runs `alembic upgrade head` to apply pending migrations.
For fresh databases: stamps the baseline revision (tables already created by init_db).

Note: Alembic commands are run in a subprocess because env.py uses asyncio.run()
which conflicts with the already-running event loop in the FastAPI lifespan.
"""

import logging
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text

from .database import async_session_maker, engine, Base

logger = logging.getLogger(__name__)

PROJECT_DIR = str(Path(__file__).resolve().parents[2])


async def _has_alembic_table() -> bool:
    """Check if alembic_version table exists in PostgreSQL."""
    async with async_session_maker() as session:
        result = await session.execute(
            text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM information_schema.tables "
                "  WHERE table_name = 'alembic_version'"
                ")"
            )
        )
        return result.scalar()


def _run_alembic(*args: str) -> None:
    """Run an Alembic command in a subprocess to avoid event loop conflicts."""
    cmd = [sys.executable, "-m", "alembic"] + list(args)
    result = subprocess.run(
        cmd,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        logger.error(f"Alembic command failed: {result.stderr}")
        raise RuntimeError(f"Alembic {args[0]} failed: {result.stderr.strip()}")
    if result.stdout.strip():
        for line in result.stdout.strip().split("\n"):
            logger.info(f"alembic: {line}")


async def run_pg_migrations() -> None:
    """Run Alembic migrations on startup.

    - If alembic_version table doesn't exist (fresh install or pre-Alembic DB),
      stamps the baseline revision so future migrations work.
    - If alembic_version exists, runs upgrade head to apply pending migrations.
    """
    has_table = await _has_alembic_table()
    if not has_table:
        async with engine.begin() as conn:
            existing = (await conn.execute(text("SELECT to_regclass('public.devices_device')"))).scalar()
            if not existing:
                # A genuinely empty database can be created at the current schema.
                await conn.run_sync(Base.metadata.create_all)
            else:
                # Pre-Alembic ZenShield already has the baseline tables. Preserve
                # their types/data; the historical e9 migration drops Django tables.
                from ..models.llm_config import LLMConfig
                await conn.run_sync(lambda sync: LLMConfig.__table__.create(sync, checkfirst=True))
        _run_alembic("stamp", "e9a05a29e536" if existing else "head")
    _run_alembic("upgrade", "head")
    logger.info("PostgreSQL migrations up to date")
