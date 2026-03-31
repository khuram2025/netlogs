"""
Redis client singleton for Zentryc.

Used for: sessions, rate limiting, caching, pub/sub, log streams, task queue.
"""

import logging
from typing import Optional

import redis.asyncio as aioredis

from .config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Get or create the async Redis client singleton."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        logger.info(f"Redis client connected to {settings.redis_url}")
    return _redis_client


async def close_redis() -> None:
    """Close the Redis connection on shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection closed")


async def redis_health_check() -> bool:
    """Check if Redis is reachable. Returns True if healthy."""
    try:
        client = await get_redis()
        return await client.ping()
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        return False
