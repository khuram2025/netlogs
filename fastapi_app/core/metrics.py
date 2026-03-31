"""
Prometheus metrics for Zentryc SIEM platform.

Exposes /metrics endpoint with HTTP, database, and business metrics.
"""

from prometheus_client import Counter, Histogram, Gauge
from prometheus_fastapi_instrumentator import Instrumentator

# ============================================================
# Custom metrics
# ============================================================

# Authentication
LOGIN_TOTAL = Counter(
    "zentryc_login_total",
    "Total login attempts",
    ["status"],  # success, failed, locked
)

ACTIVE_SESSIONS = Gauge(
    "zentryc_active_sessions",
    "Number of active sessions in Redis",
)

# API Keys
API_KEY_REQUESTS = Counter(
    "zentryc_api_key_requests_total",
    "API key authenticated requests",
    ["status"],  # success, rate_limited, invalid, expired
)

# Database
DB_QUERY_DURATION = Histogram(
    "zentryc_db_query_duration_seconds",
    "Database query duration",
    ["database"],  # postgres, clickhouse
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Alerts
ALERTS_FIRED = Counter(
    "zentryc_alerts_fired_total",
    "Alerts fired by the alert engine",
    ["severity"],  # critical, high, medium, low
)

ALERT_RULES_EVALUATED = Counter(
    "zentryc_alert_rules_evaluated_total",
    "Alert rules evaluated per cycle",
)

# Syslog (populated by syslog collector if running in same process)
SYSLOG_EPS = Gauge(
    "zentryc_syslog_eps",
    "Current events per second rate",
)

# System
APP_INFO = Gauge(
    "zentryc_app_info",
    "Application version info",
    ["version"],
)


def setup_instrumentator() -> Instrumentator:
    """Create and configure the Prometheus instrumentator for FastAPI."""
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        excluded_handlers=["/metrics", "/api/health/simple"],
        env_var_name="ENABLE_METRICS",
        inprogress_name="zentryc_http_requests_inprogress",
        inprogress_labels=True,
    )

    # Add default metrics: request count, latency histogram, response size
    instrumentator.add(
        default_instrumentation_with_labels()
    )

    return instrumentator


def default_instrumentation_with_labels():
    """Custom instrumentation that adds method and handler labels."""
    from prometheus_fastapi_instrumentator.metrics import Info
    from prometheus_client import Histogram as PromHistogram

    REQUEST_DURATION = PromHistogram(
        "zentryc_http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "handler", "status"],
        buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )

    def instrumentation(info: Info) -> None:
        if info.modified_handler:
            handler = info.modified_handler
        else:
            handler = info.request.url.path
        REQUEST_DURATION.labels(
            method=info.request.method,
            handler=handler,
            status=info.modified_status,
        ).observe(info.modified_duration)

    return instrumentation
