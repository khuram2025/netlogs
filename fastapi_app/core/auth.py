"""
Authentication utilities - JWT session tokens, login/logout, middleware.

Sessions are stored in Redis (survives restarts, shared across workers).
Falls back to in-memory if Redis is unavailable.
"""

import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request, Response, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from ..db.database import get_db, async_session_maker
from ..models.user import User

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
SESSION_COOKIE_NAME = "zentryc_session"
SESSION_EXPIRY_HOURS = 8
REMEMBER_ME_DAYS = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Redis key prefix for sessions
_SESSION_PREFIX = "session:"

# In-memory fallback (used only when Redis is unavailable)
_revoked_tokens_fallback: dict[str, float] = {}


async def store_session(jti: str, user_id: int, username: str, role: str, ttl_seconds: int) -> None:
    """Store an active session in Redis. Falls back to no-op if Redis unavailable."""
    try:
        from .cache import get_redis
        redis = await get_redis()
        await redis.setex(f"{_SESSION_PREFIX}{jti}", ttl_seconds, f"{user_id}:{username}:{role}")
        logger.debug(f"Session stored in Redis: session:{jti[:8]}... ttl={ttl_seconds}s user={username}")
    except Exception as e:
        logger.debug(f"Redis session store unavailable, using stateless JWT: {e}")


async def revoke_token(jti: str, exp_timestamp: float) -> None:
    """Revoke a session by deleting it from Redis (e.g. on logout)."""
    try:
        from .cache import get_redis
        redis = await get_redis()
        await redis.delete(f"{_SESSION_PREFIX}{jti}")
    except Exception:
        # Fallback: mark in memory
        _revoked_tokens_fallback[jti] = exp_timestamp


async def is_token_revoked(jti: str) -> bool:
    """Check if a token's session has been revoked.
    In Redis mode: session key must exist (deleted = revoked).
    Fallback: check in-memory revocation set."""
    try:
        from .cache import get_redis
        redis = await get_redis()
        exists = await redis.exists(f"{_SESSION_PREFIX}{jti}")
        return not exists  # If key doesn't exist, session was revoked/expired
    except Exception:
        # Fallback: check in-memory
        return jti in _revoked_tokens_fallback


# ============================================================
# Password complexity
# ============================================================
PASSWORD_MIN_LENGTH = 8
PASSWORD_RULES = "at least 8 characters, with uppercase, lowercase, and a digit"


def validate_password_strength(password: str) -> Optional[str]:
    """Return an error message if password is too weak, or None if OK."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    return None

# Paths that don't require authentication
PUBLIC_PATHS = {
    "/auth/login",
    "/setup",
    "/api/setup",
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/static",
    "/favicon.ico",
    "/metrics",
}


async def create_session_token(user_id: int, username: str, role: str, remember_me: bool = False) -> str:
    """Create a JWT session token and register the session in Redis."""
    if remember_me:
        ttl = timedelta(days=REMEMBER_ME_DAYS)
    else:
        ttl = timedelta(hours=SESSION_EXPIRY_HOURS)

    expire = datetime.now(timezone.utc) + ttl
    jti = uuid.uuid4().hex

    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": jti,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

    # Store session in Redis with matching TTL
    await store_session(jti, user_id, username, role, int(ttl.total_seconds()))

    return token


async def decode_session_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT session token.
    Returns None if expired, invalid signature, or revoked."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        # Check if this specific token has been revoked (e.g. logout)
        jti = payload.get("jti")
        if jti and await is_token_revoked(jti):
            return None
        return payload
    except InvalidTokenError:
        return None


def is_public_path(path: str) -> bool:
    """Check if a path is public (doesn't require authentication)."""
    for public_path in PUBLIC_PATHS:
        if path == public_path or path.startswith(public_path + "/") or path.startswith(public_path + "?"):
            return True
    # EDL feed URLs are public (for firewall consumption)
    if path.startswith("/edl/feed/"):
        return True
    # Individual list feed endpoints like /edl/123/feed/
    if path.startswith("/edl/") and "/feed/" in path:
        return True
    return False


async def get_current_user(request: Request) -> Optional[User]:
    """Get the current authenticated user from the session cookie.
    Returns None if not authenticated. For use as a FastAPI dependency."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    payload = await decode_session_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    async with async_session_maker() as session:
        result = await session.execute(
            select(User).where(User.id == int(user_id), User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if user:
            # Attach role from token for quick access
            request.state.current_user = user
            request.state.user_role = user.role
        return user


async def require_auth(request: Request) -> User:
    """Dependency that requires authentication. Raises 401 if not authenticated."""
    user = await get_current_user(request)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/auth/login?next={request.url.path}"},
        )
    return user


async def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate a user by username and password.
    Handles failed login attempts and account lockout."""
    async with async_session_maker() as session:
        result = await session.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()

        if user is None:
            return None

        # Check if account is locked
        if user.is_locked:
            logger.warning(f"Login attempt for locked account: {username}")
            return None

        # Verify password
        if not user.verify_password(password):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

            # Lock account after MAX_FAILED_ATTEMPTS
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                logger.warning(f"Account locked due to {MAX_FAILED_ATTEMPTS} failed attempts: {username}")

            await session.commit()
            return None

        # Successful login - reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        await session.commit()

        return user


def set_session_cookie(response: Response, token: str, remember_me: bool = False):
    """Set the session cookie on the response."""
    max_age = REMEMBER_ME_DAYS * 24 * 3600 if remember_me else SESSION_EXPIRY_HOURS * 3600
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
    )


def clear_session_cookie(response: Response):
    """Clear the session cookie."""
    response.delete_cookie(key=SESSION_COOKIE_NAME)


# ============================================================
# API Key Authentication
# ============================================================

# In-memory rate limit tracking: {key_prefix: [(timestamp, ...),]}
_api_key_rate_limits: dict[str, list[float]] = {}
API_KEY_RATE_LIMIT = 100  # requests per minute
API_KEY_RATE_WINDOW = 60  # seconds


def check_api_key_rate_limit(key_prefix: str) -> bool:
    """Check if an API key has exceeded its rate limit.
    Returns True if allowed, False if rate-limited."""
    import time
    now = time.time()
    window_start = now - API_KEY_RATE_WINDOW

    if key_prefix not in _api_key_rate_limits:
        _api_key_rate_limits[key_prefix] = []

    # Prune old entries
    _api_key_rate_limits[key_prefix] = [
        t for t in _api_key_rate_limits[key_prefix] if t > window_start
    ]

    if len(_api_key_rate_limits[key_prefix]) >= API_KEY_RATE_LIMIT:
        return False

    _api_key_rate_limits[key_prefix].append(now)
    return True


async def authenticate_api_key(request: Request) -> Optional[User]:
    """Authenticate a request using an API key.
    Checks X-API-Key header and api_key query param.
    Returns the User associated with the key, or None."""
    from ..models.api_key import APIKey

    # Extract key from header or query param
    api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if not api_key:
        return None

    key_hash = APIKey.hash_key(api_key)
    key_prefix = api_key[:8] if len(api_key) >= 8 else api_key

    # Rate limit check
    if not check_api_key_rate_limit(key_prefix):
        request.state.api_key_rate_limited = True
        return None

    async with async_session_maker() as session:
        result = await session.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
            )
        )
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj:
            return None

        # Check expiration
        if api_key_obj.is_expired:
            return None

        # Get associated user
        user_result = await session.execute(
            select(User).where(User.id == api_key_obj.user_id, User.is_active == True)
        )
        user = user_result.scalar_one_or_none()

        if not user:
            return None

        # Update last_used_at
        api_key_obj.last_used_at = datetime.now(timezone.utc)
        await session.commit()

        # Attach API key info to request state
        request.state.current_user = user
        request.state.user_role = user.role
        request.state.api_key = api_key_obj
        request.state.api_key_permissions = api_key_obj.permissions or ["read"]

        return user
