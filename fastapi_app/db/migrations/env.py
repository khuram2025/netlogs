"""
Alembic migration environment - configured for Zentryc async PostgreSQL.
"""

import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Ensure the project root is on sys.path so imports work
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

# Import our app's Base and all models so metadata is populated
from fastapi_app.db.database import Base, get_database_url

# Import ALL models to register them with Base.metadata
from fastapi_app.models import device  # noqa: F401
from fastapi_app.models import credential  # noqa: F401
from fastapi_app.models import routing  # noqa: F401
from fastapi_app.models import device_ssh_settings  # noqa: F401
from fastapi_app.models import zone  # noqa: F401
from fastapi_app.models import project  # noqa: F401
from fastapi_app.models import edl  # noqa: F401
from fastapi_app.models import storage_settings  # noqa: F401
from fastapi_app.models import user  # noqa: F401
from fastapi_app.models import alert  # noqa: F401
from fastapi_app.models import api_key  # noqa: F401
from fastapi_app.models import threat_intel  # noqa: F401
from fastapi_app.models import correlation  # noqa: F401
from fastapi_app.models import saved_search  # noqa: F401
from fastapi_app.models import dashboard  # noqa: F401
from fastapi_app.models import address_object  # noqa: F401
from fastapi_app.models import system_settings  # noqa: F401

# Alembic Config object
config = context.config

# Set up Python logging from the .ini file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Point Alembic at our app's metadata for autogenerate support
target_metadata = Base.metadata


def get_url() -> str:
    """Get the database URL from our app config."""
    return get_database_url()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL script generation)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in async mode with our database URL."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
