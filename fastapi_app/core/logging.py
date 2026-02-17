"""
Logging configuration for the application.
Supports both text and structured JSON output formats.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import settings


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for machine-readable output."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        if record.funcName and record.funcName != "<module>":
            log_entry["function"] = record.funcName
        if record.lineno:
            log_entry["line"] = record.lineno
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Include any extra fields added via logger.info("msg", extra={...})
        for key in ("user", "ip", "action", "resource", "request_id"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        return json.dumps(log_entry, default=str, ensure_ascii=False)


def _get_module_log_level(module_name: str) -> str | None:
    """Check for per-module log level override via env vars.

    Example: LOG_LEVEL_AUTH=DEBUG sets fastapi_app.core.auth to DEBUG.
    Format: LOG_LEVEL_<MODULE>=<LEVEL> (case-insensitive).
    """
    # Try exact module suffix: e.g. LOG_LEVEL_SYSLOG for ...syslog_collector
    short = module_name.rsplit(".", 1)[-1].upper()
    env_key = f"LOG_LEVEL_{short}"
    return os.environ.get(env_key)


def setup_logging() -> None:
    """Configure application logging."""

    # Create logs directory if it doesn't exist
    log_dir = Path(settings.log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    use_json = settings.log_format.lower() == "json"

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if settings.debug else logging.INFO)

    if use_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_format)

    # File handler with rotation — always includes function/line info
    file_handler = RotatingFileHandler(
        settings.log_file,
        maxBytes=settings.log_max_size,
        backupCount=settings.log_backup_count,
    )
    file_handler.setLevel(logging.DEBUG)

    if use_json:
        file_handler.setFormatter(JSONFormatter())
    else:
        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)

    # Clear existing handlers and add new ones
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Set specific logger levels (defaults)
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.DEBUG if settings.debug else logging.WARNING
    )
    logging.getLogger("clickhouse_connect").setLevel(logging.WARNING)

    # Apply per-module log level overrides from env vars
    _apply_module_overrides()


def _apply_module_overrides() -> None:
    """Apply LOG_LEVEL_<MODULE>=<LEVEL> environment variable overrides."""
    prefix = "LOG_LEVEL_"
    for key, value in os.environ.items():
        if key.startswith(prefix) and key != "LOG_LEVEL":
            module_suffix = key[len(prefix):].lower()
            level = getattr(logging, value.upper(), None)
            if level is None:
                continue
            # Apply to any logger whose name ends with this suffix
            # e.g., LOG_LEVEL_AUTH → fastapi_app.core.auth
            for name in list(logging.Logger.manager.loggerDict.keys()):
                if name.lower().endswith(module_suffix) or name.lower().endswith("." + module_suffix):
                    logging.getLogger(name).setLevel(level)
            # Also set a catch-all for loggers created later
            logging.getLogger(f"fastapi_app.core.{module_suffix}").setLevel(level)
            logging.getLogger(f"fastapi_app.api.{module_suffix}").setLevel(level)
            logging.getLogger(f"fastapi_app.services.{module_suffix}").setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)
