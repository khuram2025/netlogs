"""
ClickHouse migration runner.
Tracks applied migrations in PostgreSQL system_settings table.
Migrations are numbered Python files: 001_description.py, 002_description.py, etc.
Each must define an `upgrade(client)` function that receives a ClickHouse client.
"""

import importlib
import logging
from pathlib import Path

from ..clickhouse import ClickHouseClient
from ..database import async_session_maker
from sqlalchemy import select

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent
CH_VERSION_KEY = "clickhouse_schema_version"


def _discover_migrations() -> list[tuple[int, str, Path]]:
    """Find all migration scripts in order. Returns [(version, name, path), ...]."""
    migrations = []
    for p in sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.py")):
        version = int(p.stem.split("_", 1)[0])
        name = p.stem
        migrations.append((version, name, p))
    return migrations


async def _get_current_version() -> int:
    """Get current ClickHouse schema version from PostgreSQL."""
    from ...models.system_settings import SystemSetting

    async with async_session_maker() as session:
        result = await session.execute(
            select(SystemSetting).where(SystemSetting.key == CH_VERSION_KEY)
        )
        setting = result.scalar_one_or_none()
        if setting:
            return int(setting.value)
        return 0


async def _set_current_version(version: int) -> None:
    """Update ClickHouse schema version in PostgreSQL."""
    from ...models.system_settings import SystemSetting
    from datetime import datetime, timezone

    async with async_session_maker() as session:
        result = await session.execute(
            select(SystemSetting).where(SystemSetting.key == CH_VERSION_KEY)
        )
        setting = result.scalar_one_or_none()
        if setting:
            setting.value = str(version)
            setting.updated_at = datetime.now(timezone.utc)
        else:
            setting = SystemSetting(
                key=CH_VERSION_KEY,
                value=str(version),
            )
            session.add(setting)
        await session.commit()


async def run_clickhouse_migrations() -> int:
    """Run all pending ClickHouse migrations. Returns count of applied migrations."""
    current = await _get_current_version()
    migrations = _discover_migrations()
    pending = [(v, name, p) for v, name, p in migrations if v > current]

    if not pending:
        logger.debug(f"ClickHouse schema at version {current}, no migrations pending")
        return 0

    client = ClickHouseClient.get_client()
    applied = 0

    for version, name, path in pending:
        logger.info(f"Applying ClickHouse migration {name}...")
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            if hasattr(mod, "upgrade"):
                mod.upgrade(client)
                await _set_current_version(version)
                applied += 1
                logger.info(f"ClickHouse migration {name} applied successfully")
            else:
                logger.warning(f"ClickHouse migration {name} has no upgrade() function, skipping")
        except Exception as e:
            logger.error(f"ClickHouse migration {name} failed: {e}")
            raise

    return applied
