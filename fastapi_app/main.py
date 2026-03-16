"""
Zentryc SOAR/SIEM Platform - FastAPI Application
Main application entry point.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .core.config import settings
from .core.logging import setup_logging
from .__version__ import __version__
from .core.auth import is_public_path, get_current_user, authenticate_api_key, SESSION_COOKIE_NAME
from .core.csrf import CSRFMiddleware
from .db.database import init_db, close_db
from .db.clickhouse import ClickHouseClient
from .api.devices import router as devices_api_router
from .api.logs import router as logs_api_router
from .api.views import router as views_router
from .api.projects import router as projects_router
from .api.edl import router as edl_router
from .api.auth import router as auth_router
from .api.users import router as users_router
from .api.alerts import router as alerts_router
from .api.api_keys import router as api_keys_router
from .api.threat_intel import router as threat_intel_router
from .api.correlation import router as correlation_router
from .api.saved_searches import router as saved_searches_router
from .api.dashboards import router as dashboards_router
from .api.address_objects import router as address_objects_router
from .api.setup import router as setup_router
from .api.health import router as health_router
from .api.backup import router as backup_router
from .api.llm_config import router as llm_config_router
from .api.threat_dashboard import router as threat_dashboard_router
from .services.scheduler import start_scheduler, stop_scheduler


# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce authentication on all routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public paths
        if is_public_path(path):
            response = await call_next(request)
            return response

        # Redirect to setup wizard if first-run setup is needed
        if not path.startswith("/setup") and not path.startswith("/api/setup"):
            from .services.setup_service import is_setup_needed
            if await is_setup_needed():
                return RedirectResponse(url="/setup", status_code=303)

        # Check for session cookie
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            # For API paths, also try API key authentication
            if path.startswith("/api/"):
                api_user = await authenticate_api_key(request)
                if api_user:
                    # API key auth succeeded
                    response = await call_next(request)
                    return response
                # Check if rate-limited
                if getattr(request.state, "api_key_rate_limited", False):
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limit exceeded. Max 100 requests per minute."},
                    )
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Not authenticated"},
                )
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=303)

        # Validate session
        user = await get_current_user(request)
        if user is None:
            # For API paths, also try API key as fallback
            if path.startswith("/api/"):
                api_user = await authenticate_api_key(request)
                if api_user:
                    response = await call_next(request)
                    return response
                if getattr(request.state, "api_key_rate_limited", False):
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limit exceeded. Max 100 requests per minute."},
                    )
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Session expired or invalid"},
                )
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=303)

        response = await call_next(request)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    logger.info("Starting Zentryc SOAR/SIEM Platform...")

    # Initialize PostgreSQL database
    try:
        await init_db()
        logger.info("PostgreSQL database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL: {e}")

    # Run Alembic migrations (stamp if fresh install, upgrade if pending)
    try:
        from .db.migrate import run_pg_migrations
        await run_pg_migrations()
    except Exception as e:
        logger.warning(f"Alembic migration check: {e}")

    # Initialize ClickHouse tables
    try:
        ClickHouseClient.ensure_table()
        logger.info("ClickHouse table verified")
    except Exception as e:
        logger.warning(f"ClickHouse setup warning: {e}")

    # Initialize Palo Alto threat/URL dedicated table + materialized views
    try:
        ClickHouseClient.ensure_pa_threat_table()
        logger.info("ClickHouse pa_threat_logs table verified")
    except Exception as e:
        logger.warning(f"PA threat table setup warning: {e}")

    # Run ClickHouse migrations
    try:
        from .db.clickhouse_migrations.runner import run_clickhouse_migrations
        applied = await run_clickhouse_migrations()
        if applied:
            logger.info(f"Applied {applied} ClickHouse migration(s)")
    except Exception as e:
        logger.warning(f"ClickHouse migration check: {e}")

    # Initialize ClickHouse audit logs table
    try:
        from .services.audit_service import ensure_audit_table
        ensure_audit_table()
        logger.info("ClickHouse audit_logs table verified")
    except Exception as e:
        logger.warning(f"Audit table setup warning: {e}")

    # Initialize ClickHouse IOC matches table
    try:
        from .services.threat_intel_service import ensure_ioc_matches_table, seed_builtin_feeds
        ensure_ioc_matches_table()
        logger.info("ClickHouse ioc_matches table verified")
    except Exception as e:
        logger.warning(f"IOC matches table setup warning: {e}")

    # Seed built-in threat intelligence feeds
    try:
        await seed_builtin_feeds()
        logger.info("Built-in threat feeds seeded")
    except Exception as e:
        logger.warning(f"Threat feed seeding warning: {e}")

    # Initialize correlation engine
    try:
        from .services.correlation_engine import ensure_correlation_matches_table, seed_correlation_rules
        ensure_correlation_matches_table()
        await seed_correlation_rules()
        logger.info("Correlation engine initialized")
    except Exception as e:
        logger.warning(f"Correlation engine setup warning: {e}")

    # Load IOC cache for real-time matching
    try:
        from .services.ioc_matcher import refresh_ioc_cache, ensure_auto_block_edl
        await refresh_ioc_cache()
        logger.info("IOC matcher cache loaded")
        await ensure_auto_block_edl()
        logger.info("Auto-block EDL list ensured")
    except Exception as e:
        logger.warning(f"IOC cache/auto-block setup warning: {e}")

    # Start background scheduler for routing table collection
    try:
        start_scheduler()
        logger.info("Background scheduler started")
    except Exception as e:
        logger.warning(f"Scheduler setup warning: {e}")

    logger.info(f"Application ready on {settings.host}:{settings.port}")

    yield

    # Shutdown
    logger.info("Shutting down Zentryc...")
    stop_scheduler()
    ClickHouseClient.close_client()
    await close_db()
    logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Enterprise Firewall Log Management and SIEM Platform",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else settings.allowed_hosts_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CSRF middleware - validates tokens on state-changing requests
app.add_middleware(CSRFMiddleware)

# Authentication middleware - must be added AFTER CORS and CSRF
app.add_middleware(AuthenticationMiddleware)


# Mount static files
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    # Static directory doesn't exist
    pass


# Include setup wizard (must be before auth routes)
app.include_router(setup_router)

# Include auth routes (must be before other routes)
app.include_router(auth_router)

# Include API routers
app.include_router(devices_api_router, prefix="/api")
app.include_router(logs_api_router, prefix="/api")

# Include HTML view routes
app.include_router(views_router)
app.include_router(projects_router)
app.include_router(edl_router)
app.include_router(users_router)
app.include_router(alerts_router)
app.include_router(api_keys_router)
app.include_router(threat_intel_router)
app.include_router(correlation_router)
app.include_router(saved_searches_router)
app.include_router(dashboards_router)
app.include_router(address_objects_router)

# Include health check routes (public, no auth)
app.include_router(health_router)

# Include backup management routes
app.include_router(backup_router)

# Include LLM configuration routes
app.include_router(llm_config_router)

# Include Palo Alto threat/URL dashboard routes
app.include_router(threat_dashboard_router)


@app.get("/api/")
async def api_root():
    """API root endpoint."""
    return {
        "message": "Zentryc SOAR/SIEM API",
        "version": __version__,
        "endpoints": {
            "devices": "/api/devices/",
            "logs": "/api/logs/",
            "projects": "/api/projects/",
            "edl": "/api/edl/",
            "health": "/api/health",
            "docs": "/api/docs",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "fastapi_app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
