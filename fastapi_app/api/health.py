"""
Enhanced health check endpoint with component status monitoring.
Reports on PostgreSQL, ClickHouse, scheduler, and syslog status.
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..__version__ import __version__
from ..core.config import settings
from ..db.database import async_session_maker
from ..db.clickhouse import ClickHouseClient

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# Track application start time for uptime calculation
_app_start_time: float = time.time()


def get_uptime_seconds() -> int:
    return int(time.time() - _app_start_time)


async def _check_postgresql() -> dict:
    """Check PostgreSQL connectivity and measure latency."""
    start = time.monotonic()
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
            result.scalar()
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return {"status": "healthy", "latency_ms": latency_ms}
    except Exception as e:
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return {"status": "unhealthy", "latency_ms": latency_ms, "error": str(e)}


def _check_clickhouse() -> dict:
    """Check ClickHouse connectivity and measure latency."""
    start = time.monotonic()
    try:
        client = ClickHouseClient.get_client()
        result = client.query("SELECT 1")
        latency_ms = round((time.monotonic() - start) * 1000, 1)

        # Get table row count as an extra health signal
        try:
            row_result = client.query("SELECT count() FROM syslogs")
            total_rows = row_result.first_row[0] if row_result.result_rows else 0
        except Exception:
            total_rows = None

        info = {"status": "healthy", "latency_ms": latency_ms}
        if total_rows is not None:
            info["total_rows"] = total_rows
        return info
    except Exception as e:
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return {"status": "unhealthy", "latency_ms": latency_ms, "error": str(e)}


def _check_scheduler() -> dict:
    """Check APScheduler status and running jobs."""
    try:
        from ..services.scheduler import get_scheduler_status
        status = get_scheduler_status()
        job_count = len(status.get("jobs", []))
        if status.get("running"):
            return {
                "status": "healthy",
                "jobs_running": job_count,
                "jobs": status["jobs"],
            }
        else:
            return {"status": "degraded", "jobs_running": 0, "detail": "Scheduler not running (may be locked to another worker)"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def _check_syslog() -> dict:
    """Check syslog collector status by querying recent log ingest."""
    try:
        client = ClickHouseClient.get_client()
        # Count logs in last 5 minutes to gauge ingest health
        result = client.query(
            "SELECT count() as cnt, "
            "round(count() / 300, 1) as eps "
            "FROM syslogs WHERE timestamp >= now() - INTERVAL 5 MINUTE"
        )
        if result.result_rows:
            count = result.first_row[0]
            eps = result.first_row[1]
        else:
            count = 0
            eps = 0.0

        status = "healthy" if count > 0 else "degraded"
        return {
            "status": status,
            "recent_events_5m": count,
            "current_eps": float(eps),
            "port": settings.syslog_port,
        }
    except Exception as e:
        return {"status": "unknown", "error": str(e), "port": settings.syslog_port}


@router.get("/api/health", name="health_check")
async def health_check(request: Request):
    """Enhanced health check endpoint with component status."""
    # Check all components
    pg_status = await _check_postgresql()
    ch_status = _check_clickhouse()
    sched_status = _check_scheduler()
    syslog_status = _check_syslog()

    components = {
        "postgresql": pg_status,
        "clickhouse": ch_status,
        "scheduler": sched_status,
        "syslog": syslog_status,
    }

    # Determine overall status
    statuses = [c["status"] for c in components.values()]
    if all(s == "healthy" for s in statuses):
        overall = "healthy"
    elif any(s == "unhealthy" for s in statuses):
        overall = "unhealthy"
    else:
        overall = "degraded"

    response = {
        "status": overall,
        "version": __version__,
        "uptime_seconds": get_uptime_seconds(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }

    # Return 503 if unhealthy (helps Docker/LB health checks)
    status_code = 200 if overall != "unhealthy" else 503
    return JSONResponse(response, status_code=status_code)


@router.get("/api/health/simple", name="health_check_simple")
async def health_check_simple():
    """Simple health check for Docker/load balancer probes. Fast, no DB calls."""
    return {"status": "ok", "version": __version__}
