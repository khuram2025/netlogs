"""Ensure reproducible NQL and traffic analytics fields on every appliance."""
def upgrade(client):
    from fastapi_app.db.clickhouse import ClickHouseClient
    ClickHouseClient.ensure_analytics_columns()
