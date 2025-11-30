"""
Application configuration using Pydantic Settings.
Loads from environment variables and .env file.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "NetLogs SOAR/SIEM Platform"
    debug: bool = Field(default=False, alias="DEBUG")
    secret_key: str = Field(default="change-me-in-production", alias="SECRET_KEY")
    allowed_hosts: str = Field(default="*", alias="ALLOWED_HOSTS")

    # Server
    host: str = Field(default="0.0.0.0", alias="SERVER_HOST")
    port: int = Field(default=8000, alias="SERVER_PORT")

    # PostgreSQL Database
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_db: str = Field(default="netlogs", alias="POSTGRES_DB")
    postgres_user: str = Field(default="read", alias="POSTGRES_USER")
    postgres_password: str = Field(default="Read@123", alias="POSTGRES_PASSWORD")

    # ClickHouse
    clickhouse_host: str = Field(default="localhost", alias="CLICKHOUSE_HOST")
    clickhouse_port: int = Field(default=8123, alias="CLICKHOUSE_PORT")
    clickhouse_user: str = Field(default="default", alias="CLICKHOUSE_USER")
    clickhouse_password: str = Field(default="", alias="CLICKHOUSE_PASSWORD")
    clickhouse_db: str = Field(default="default", alias="CLICKHOUSE_DB")

    # Syslog Collector
    syslog_port: int = Field(default=514, alias="SYSLOG_PORT")
    syslog_batch_size: int = Field(default=5000, alias="SYSLOG_BATCH_SIZE")
    syslog_flush_interval: float = Field(default=2.0, alias="SYSLOG_FLUSH_INTERVAL")
    syslog_cache_ttl: int = Field(default=60, alias="SYSLOG_CACHE_TTL")
    syslog_workers: int = Field(default=4, alias="SYSLOG_WORKERS")
    syslog_max_buffer: int = Field(default=100000, alias="SYSLOG_MAX_BUFFER")
    syslog_metrics_interval: int = Field(default=30, alias="SYSLOG_METRICS_INTERVAL")

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/netlogs.log", alias="LOG_FILE")
    log_max_size: int = Field(default=10485760, alias="LOG_MAX_SIZE")  # 10MB
    log_backup_count: int = Field(default=5, alias="LOG_BACKUP_COUNT")

    # Timezone
    timezone: str = Field(default="Asia/Riyadh", alias="TZ")

    @property
    def postgres_url(self) -> str:
        """Build PostgreSQL connection URL."""
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def postgres_sync_url(self) -> str:
        """Build PostgreSQL sync connection URL for migrations."""
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def allowed_hosts_list(self) -> List[str]:
        """Parse allowed hosts into a list."""
        if self.allowed_hosts == "*":
            return ["*"]
        return [h.strip() for h in self.allowed_hosts.split(",")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
