"""Expose historical batches alongside live analytics, preserving existing data."""
from fastapi_app.db.analytics_backfill import TARGETS, ensure_ledger, ensure_history_view


def upgrade(client):
    ensure_ledger(client)
    for target in TARGETS:
        ensure_history_view(client, target)
