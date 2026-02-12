"""
Audit logging service - logs all admin actions to ClickHouse for compliance.

Immutable audit trail with automatic TTL (1 year retention).
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..db.clickhouse import ClickHouseClient

logger = logging.getLogger(__name__)


def ensure_audit_table():
    """Create the audit_logs table in ClickHouse if it doesn't exist."""
    try:
        client = ClickHouseClient.get_client()
        client.command("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                timestamp DateTime64(3),
                user_id UInt32,
                username String,
                action String,
                resource_type String,
                resource_id String,
                resource_name String,
                details String,
                ip_address String,
                user_agent String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, user_id)
            TTL toDateTime(timestamp) + INTERVAL 1 YEAR DELETE
        """)
        logger.info("Audit logs table ensured in ClickHouse")
    except Exception as e:
        logger.error(f"Failed to create audit_logs table: {e}")


def log_action(
    user_id: int = 0,
    username: str = "",
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    resource_name: str = "",
    details: Optional[Dict[str, Any]] = None,
    ip_address: str = "",
    user_agent: str = "",
):
    """Log an audit event to ClickHouse.

    Args:
        user_id: The acting user's ID (0 for system/anonymous)
        username: The acting user's username
        action: Action performed (login, logout, create, update, delete, etc.)
        resource_type: Type of resource (user, device, alert_rule, edl, project, etc.)
        resource_id: ID of the resource affected
        resource_name: Human-readable name of the resource
        details: Additional details as a dict (serialized to JSON)
        ip_address: Client IP address
        user_agent: Client user-agent string
    """
    try:
        client = ClickHouseClient.get_client()
        details_str = json.dumps(details) if details else "{}"

        client.insert(
            "audit_logs",
            [[
                datetime.now(timezone.utc),
                user_id,
                username,
                action,
                resource_type,
                str(resource_id),
                resource_name,
                details_str,
                ip_address,
                user_agent[:500] if user_agent else "",
            ]],
            column_names=[
                "timestamp", "user_id", "username", "action",
                "resource_type", "resource_id", "resource_name",
                "details", "ip_address", "user_agent",
            ],
        )
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


def log_from_request(request, action: str, resource_type: str = "",
                     resource_id: str = "", resource_name: str = "",
                     details: Optional[Dict] = None):
    """Log an audit event extracting user info from the request."""
    user = getattr(request.state, "current_user", None)
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")

    log_action(
        user_id=user.id if user else 0,
        username=user.username if user else "anonymous",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        resource_name=resource_name,
        details=details,
        ip_address=ip,
        user_agent=ua,
    )


def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> tuple:
    """Query audit logs with filters.

    Returns:
        Tuple of (logs list, total count)
    """
    try:
        client = ClickHouseClient.get_client()

        where_parts = ["1=1"]
        if username:
            where_parts.append(f"username = '{username}'")
        if action:
            where_parts.append(f"action = '{action}'")
        if resource_type:
            where_parts.append(f"resource_type = '{resource_type}'")
        if start_time:
            where_parts.append(f"timestamp >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}'")
        if end_time:
            where_parts.append(f"timestamp <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'")

        where_clause = " AND ".join(where_parts)

        # Count query
        count_result = client.query(f"SELECT count() FROM audit_logs WHERE {where_clause}")
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        # Data query
        query = f"""
            SELECT timestamp, user_id, username, action,
                   resource_type, resource_id, resource_name,
                   details, ip_address, user_agent
            FROM audit_logs
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}
        """
        result = client.query(query)

        logs = []
        for row in result.result_rows:
            logs.append({
                "timestamp": row[0].isoformat() if hasattr(row[0], 'isoformat') else str(row[0]),
                "user_id": row[1],
                "username": row[2],
                "action": row[3],
                "resource_type": row[4],
                "resource_id": row[5],
                "resource_name": row[6],
                "details": row[7],
                "ip_address": row[8],
                "user_agent": row[9],
            })

        return logs, total

    except Exception as e:
        logger.error(f"Failed to query audit logs: {e}")
        return [], 0


def get_distinct_values(column: str) -> List[str]:
    """Get distinct values for a column (for filter dropdowns)."""
    try:
        client = ClickHouseClient.get_client()
        result = client.query(
            f"SELECT DISTINCT {column} FROM audit_logs ORDER BY {column} LIMIT 100"
        )
        return [row[0] for row in result.result_rows if row[0]]
    except Exception:
        return []


def export_csv(
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> str:
    """Export audit logs as CSV string."""
    logs, _ = get_audit_logs(
        limit=10000,
        offset=0,
        username=username,
        action=action,
        resource_type=resource_type,
        start_time=start_time,
        end_time=end_time,
    )

    lines = ["timestamp,username,action,resource_type,resource_id,resource_name,details,ip_address"]
    for log in logs:
        details = log["details"].replace('"', '""')
        name = log["resource_name"].replace('"', '""')
        lines.append(
            f'{log["timestamp"]},{log["username"]},{log["action"]},'
            f'{log["resource_type"]},{log["resource_id"]},"{name}","{details}",{log["ip_address"]}'
        )

    return "\n".join(lines)
