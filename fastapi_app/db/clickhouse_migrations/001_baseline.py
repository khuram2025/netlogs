"""
ClickHouse migration 001: Baseline.
Represents the existing v3.0 schema (syslogs, audit_logs, ioc_matches, correlation_matches).
This is a no-op — tables are already created by ensure_table() functions on startup.
"""


def upgrade(client):
    # Baseline: existing tables are already created by app startup.
    # This migration exists to establish version tracking.
    pass
