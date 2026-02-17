"""
First-run setup wizard service.
Manages setup completion state with in-memory caching.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from ..db.database import async_session_maker
from ..models.system_settings import SystemSetting

logger = logging.getLogger(__name__)

# In-memory cache — None means "not yet checked"
_setup_completed_cache: Optional[bool] = None


async def is_setup_needed() -> bool:
    """Check whether the first-run setup wizard should be shown.

    Uses an in-memory cache to avoid hitting the DB on every request.
    On first call: checks the DB for setup_completed flag, and if not set,
    checks whether the admin password is still the default 'changeme'.
    If the admin already changed their password, auto-marks setup complete.
    """
    global _setup_completed_cache

    # Fast path: already cached
    if _setup_completed_cache is True:
        return False

    try:
        async with async_session_maker() as session:
            # Check DB flag
            result = await session.execute(
                select(SystemSetting).where(SystemSetting.key == "setup_completed")
            )
            setting = result.scalar_one_or_none()

            if setting and setting.value == "true":
                _setup_completed_cache = True
                return False

            # No flag — check if admin still has default password
            from ..models.user import User
            admin_result = await session.execute(
                select(User).where(User.username == "admin").limit(1)
            )
            admin = admin_result.scalar_one_or_none()

            if admin is None:
                # No admin user at all — setup not needed (unusual state)
                _setup_completed_cache = True
                return False

            if not admin.verify_password("changeme"):
                # Admin already changed their password — auto-complete
                logger.info("Admin password already changed; auto-marking setup complete")
                await mark_setup_complete(session)
                return False

            # Default password still active — setup IS needed
            return True

    except Exception as e:
        logger.error(f"Error checking setup state: {e}")
        # On error, don't block the app — assume setup done
        return False


async def mark_setup_complete(session=None) -> None:
    """Write setup_completed=true to DB and update cache."""
    global _setup_completed_cache

    async def _write(sess):
        result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == "setup_completed")
        )
        setting = result.scalar_one_or_none()
        now = datetime.now(timezone.utc).isoformat()

        if setting:
            setting.value = "true"
        else:
            sess.add(SystemSetting(key="setup_completed", value="true"))

        # Also store completion timestamp
        ts_result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == "setup_completed_at")
        )
        ts_setting = ts_result.scalar_one_or_none()
        if ts_setting:
            ts_setting.value = now
        else:
            sess.add(SystemSetting(key="setup_completed_at", value=now))

        await sess.commit()

    if session:
        await _write(session)
    else:
        async with async_session_maker() as sess:
            await _write(sess)

    _setup_completed_cache = True
    logger.info("Setup wizard marked as complete")


def invalidate_setup_cache() -> None:
    """Reset the in-memory cache (e.g. for testing)."""
    global _setup_completed_cache
    _setup_completed_cache = None
