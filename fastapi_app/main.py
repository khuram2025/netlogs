"""
NetLogs SOAR/SIEM Platform - FastAPI Application
Main application entry point.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .core.logging import setup_logging
from .db.database import init_db, close_db
from .db.clickhouse import ClickHouseClient
from .api.devices import router as devices_api_router
from .api.logs import router as logs_api_router
from .api.views import router as views_router


# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    logger.info("Starting NetLogs SOAR/SIEM Platform...")

    # Initialize PostgreSQL database
    try:
        await init_db()
        logger.info("PostgreSQL database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL: {e}")

    # Initialize ClickHouse table
    try:
        ClickHouseClient.ensure_table()
        logger.info("ClickHouse table verified")
    except Exception as e:
        logger.warning(f"ClickHouse setup warning: {e}")

    logger.info(f"Application ready on {settings.host}:{settings.port}")

    yield

    # Shutdown
    logger.info("Shutting down NetLogs...")
    await close_db()
    logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Enterprise Firewall Log Management and SIEM Platform",
    version="2.0.0",
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


# Mount static files
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    # Static directory doesn't exist
    pass


# Include API routers
app.include_router(devices_api_router, prefix="/api")
app.include_router(logs_api_router, prefix="/api")

# Include HTML view routes
app.include_router(views_router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": "2.0.0"
    }


@app.get("/api/")
async def api_root():
    """API root endpoint."""
    return {
        "message": "NetLogs SOAR/SIEM API",
        "version": "2.0.0",
        "endpoints": {
            "devices": "/api/devices/",
            "logs": "/api/logs/",
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
