"""
CSRF protection middleware.

Generates a per-session CSRF token stored in a non-HttpOnly cookie (so JS can read it).
Validates the token on state-changing requests (POST, PUT, DELETE, PATCH).
Exempt: API key-authenticated requests, public paths, /api/docs endpoints.
"""

import logging
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = "zentryc_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_TOKEN_LENGTH = 32

# Methods that require CSRF validation
UNSAFE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths exempt from CSRF (API key auth, public endpoints, docs)
CSRF_EXEMPT_PREFIXES = (
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/health",
    "/edl/feed/",        # EDL feeds consumed by firewalls
)


def _is_csrf_exempt(request: Request) -> bool:
    """Check if a request is exempt from CSRF validation."""
    path = request.url.path

    for prefix in CSRF_EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return True

    # EDL individual feed endpoints
    if path.startswith("/edl/") and "/feed/" in path:
        return True

    # API key authenticated requests are exempt (machine-to-machine)
    if request.headers.get("X-API-Key") or request.query_params.get("api_key"):
        return True

    return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces CSRF token validation on unsafe methods."""

    async def dispatch(self, request: Request, call_next):
        # Get or generate CSRF token
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)

        if request.method in UNSAFE_METHODS and not _is_csrf_exempt(request):
            if not csrf_cookie:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing. Reload the page and try again."},
                )

            # Check header first, then form field
            csrf_token = request.headers.get(CSRF_HEADER_NAME)

            if not csrf_token:
                # Try to read from form body (for HTML form submissions)
                content_type = request.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                    # We need to peek at the form data
                    # Store the body so it can be re-read by the route handler
                    body = await request.body()
                    from urllib.parse import parse_qs
                    try:
                        form_data = parse_qs(body.decode("utf-8"))
                        csrf_token = form_data.get(CSRF_FORM_FIELD, [None])[0]
                    except Exception:
                        pass

            if not csrf_token or csrf_token != csrf_cookie:
                logger.warning(f"CSRF validation failed for {request.method} {request.url.path}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token invalid. Reload the page and try again."},
                )

        response = await call_next(request)

        # Set CSRF cookie if not present (readable by JS, not HttpOnly)
        if not csrf_cookie:
            csrf_cookie = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_cookie,
            max_age=8 * 3600,  # 8 hours, matches session
            httponly=False,     # JS must be able to read this
            samesite="lax",
            secure=not _is_debug(),
            path="/",
        )

        return response


def _is_debug() -> bool:
    try:
        from .config import settings
        return settings.debug
    except Exception:
        return False
