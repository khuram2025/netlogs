"""
High-performance ClickHouse client for log ingestion and querying.
Migrated from Django to FastAPI with async support.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import clickhouse_connect
from clickhouse_connect.driver import Client

from ..core.config import settings

logger = logging.getLogger(__name__)


class ClickHouseClient:
    """
    High-performance ClickHouse client optimized for log ingestion.

    Features:
    - Connection pooling (via clickhouse_connect)
    - Optimized table schema with partitioning
    - Batch insert support
    - Compression settings for storage efficiency
    """

    _client: Optional[Client] = None

    @classmethod
    def get_client(cls) -> Client:
        """Create a new client instance for thread safety."""
        try:
            return clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
                database=settings.clickhouse_db,
                compress=True,
                settings={
                    'async_insert': 1,
                    'wait_for_async_insert': 0,
                    'async_insert_max_data_size': 10000000,  # 10MB
                    'async_insert_busy_timeout_ms': 2000,
                }
            )
        except Exception as e:
            logger.error(f"Failed to connect to ClickHouse: {e}")
            raise

    @classmethod
    def ensure_table(cls) -> None:
        """
        Create optimized table schema for high-volume log ingestion.

        Optimizations:
        - PARTITION BY toYYYYMM: Monthly partitions for efficient data lifecycle
        - ORDER BY (device_ip, timestamp): Optimized for device-based queries
        - LZ4 compression: Fast compression for high-throughput ingestion
        - TTL: Automatic data expiration after 3 months
        """
        client = cls.get_client()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS syslogs (
            timestamp DateTime64(3) CODEC(DoubleDelta, LZ4),
            device_ip IPv4 CODEC(ZSTD(1)),
            facility UInt8 CODEC(T64, LZ4),
            severity UInt8 CODEC(T64, LZ4),
            message String CODEC(ZSTD(3)),
            raw String CODEC(ZSTD(3)),
            parsed_data Map(String, String) CODEC(ZSTD(1)),

            -- Materialized columns for common queries
            log_date Date MATERIALIZED toDate(timestamp),
            log_hour UInt8 MATERIALIZED toHour(timestamp),

            -- Extracted fields for fast filtering (materialized from parsed_data)
            action LowCardinality(String) MATERIALIZED mapContains(parsed_data, 'action') ? parsed_data['action'] : '',
            srcip String MATERIALIZED mapContains(parsed_data, 'srcip') ? parsed_data['srcip'] : '',
            dstip String MATERIALIZED mapContains(parsed_data, 'dstip') ? parsed_data['dstip'] : '',

            -- Indexes for common queries
            INDEX idx_severity severity TYPE minmax GRANULARITY 4,
            INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_message message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (device_ip, timestamp)
        TTL timestamp + INTERVAL 3 MONTH DELETE
        SETTINGS
            index_granularity = 8192,
            min_bytes_for_wide_part = 10485760,
            merge_with_ttl_timeout = 86400
        """

        try:
            client.command(create_table_query)
            logger.info("ClickHouse table 'syslogs' created/verified")
        except Exception as e:
            logger.warning(f"Table creation issue (may already exist): {e}")
            cls._migrate_table()

    @classmethod
    def _migrate_table(cls) -> None:
        """Migrate existing table to add new columns."""
        client = cls.get_client()
        migrations = [
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS parsed_data Map(String, String) CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_date Date MATERIALIZED toDate(timestamp)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_hour UInt8 MATERIALIZED toHour(timestamp)",
        ]
        for migration in migrations:
            try:
                client.command(migration)
            except Exception as e:
                logger.debug(f"Migration skipped: {e}")

    @classmethod
    def insert_logs(cls, logs: List[Tuple]) -> None:
        """
        Insert logs in batch.

        Args:
            logs: List of tuples matching the schema columns
                  (timestamp, device_ip, facility, severity, message, raw, parsed_data)
        """
        if not logs:
            return
        client = cls.get_client()
        client.insert('syslogs', logs, column_names=[
            'timestamp', 'device_ip', 'facility', 'severity', 'message', 'raw', 'parsed_data'
        ])

    @classmethod
    def get_recent_logs(cls, limit: int = 100) -> List[Dict[str, Any]]:
        """Get most recent logs."""
        client = cls.get_client()
        query = f"SELECT timestamp, device_ip, facility, severity, message, raw, parsed_data FROM syslogs ORDER BY timestamp DESC LIMIT {limit}"
        result = client.query(query)
        return list(result.named_results())

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Get dashboard statistics."""
        client = cls.get_client()

        # Severity counts (last 24h)
        severity_query = """
        SELECT severity, count() as count
        FROM syslogs
        WHERE timestamp > now() - INTERVAL 24 HOUR
        GROUP BY severity
        """
        severity_data = client.query(severity_query).result_rows

        # Logs per minute (last 1h)
        traffic_query = """
        SELECT toStartOfMinute(timestamp) as t, count() as count
        FROM syslogs
        WHERE timestamp > now() - INTERVAL 1 HOUR
        GROUP BY t
        ORDER BY t
        """
        traffic_data = client.query(traffic_query).result_rows

        return {
            'severity': severity_data,
            'traffic': traffic_data
        }

    @classmethod
    def _parse_advanced_query(cls, query_text: str) -> List[Dict[str, Any]]:
        """
        Parse advanced search query with field:value syntax, negation, and CIDR support.

        Supported formats:
        - srcip:192.168.1.1       (exact field match)
        - -srcip:192.168.1.1      (negated field match)
        - srcip:192.168.0.0/24    (CIDR subnet match)
        - "connection timeout"     (text search in message/raw)
        - timeout                  (text search in message/raw)
        """
        terms = []
        pattern = r'(-?)(\w+):("[^"]+"|[^\s]+)|(-?)("[^"]+"|[^\s]+)'

        for match in re.finditer(pattern, query_text):
            if match.group(2):  # field:value format
                negated = match.group(1) == '-'
                field = match.group(2).lower()
                value = match.group(3).strip('"')
                terms.append({'type': 'field', 'field': field, 'value': value, 'negated': negated})
            elif match.group(5):  # plain text
                negated = match.group(4) == '-'
                value = match.group(5).strip('"')
                terms.append({'type': 'text', 'value': value, 'negated': negated})

        return terms

    @classmethod
    def _is_cidr(cls, value: str) -> bool:
        """Check if value is CIDR notation."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value))

    @classmethod
    def _build_field_condition(cls, field: str, value: str, negated: bool = False) -> str:
        """Build SQL condition for a specific field."""
        safe_value = value.replace("'", "''")
        not_op = "!=" if negated else "="

        # Field mapping for normalized and vendor-specific fields
        field_mapping = {
            # Common normalized fields
            'srcip': "parsed_data['srcip']",
            'dstip': "parsed_data['dstip']",
            'srcport': "parsed_data['srcport']",
            'dstport': "parsed_data['dstport']",
            'action': "parsed_data['action']",
            'proto': "parsed_data['proto']",
            'app': "parsed_data['app']",
            'srcintf': "parsed_data['srcintf']",
            'dstintf': "parsed_data['dstintf']",
            'srczone': "parsed_data['srczone']",
            'dstzone': "parsed_data['dstzone']",
            'srcuser': "parsed_data['srcuser']",
            'dstuser': "parsed_data['dstuser']",
            # Fortinet-specific
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
            'policyname': "parsed_data['policyname']",
            'srccountry': "parsed_data['srccountry']",
            'dstcountry': "parsed_data['dstcountry']",
            'appcat': "parsed_data['appcat']",
            'user': "parsed_data['user']",
            # Palo Alto-specific
            'src_ip': "parsed_data['src_ip']",
            'dst_ip': "parsed_data['dst_ip']",
            'src_port': "parsed_data['src_port']",
            'dst_port': "parsed_data['dst_port']",
            'src_zone': "parsed_data['src_zone']",
            'dst_zone': "parsed_data['dst_zone']",
            'src_user': "parsed_data['src_user']",
            'dst_user': "parsed_data['dst_user']",
            'inbound_if': "parsed_data['inbound_if']",
            'outbound_if': "parsed_data['outbound_if']",
            'application': "parsed_data['application']",
            'rule': "parsed_data['rule']",
            'serial': "parsed_data['serial']",
            'vsys': "parsed_data['vsys']",
            'device_name': "parsed_data['device_name']",
            'session_id': "parsed_data['session_id']",
            'threat_id': "parsed_data['threat_id']",
            'category': "parsed_data['category']",
            'log_type': "parsed_data['log_type']",
            'nat_srcip': "parsed_data['nat_srcip']",
            'nat_dstip': "parsed_data['nat_dstip']",
            'nat_src_ip': "parsed_data['nat_src_ip']",
            'nat_dst_ip': "parsed_data['nat_dst_ip']",
            'src_location': "parsed_data['src_location']",
            'dst_location': "parsed_data['dst_location']",
            # Common fields
            'type': "parsed_data['type']",
            'subtype': "parsed_data['subtype']",
            'device': "toString(device_ip)",
            'severity': "severity",
        }

        col_expr = field_mapping.get(field, f"parsed_data['{field}']")

        # Handle CIDR notation for IP fields
        if field in ('srcip', 'dstip') and cls._is_cidr(value):
            if negated:
                return f"multiIf({col_expr} = '', 1, isNull(IPv4StringToNumOrNull({col_expr})), 1, NOT isIPAddressInRange({col_expr}, '{safe_value}'), 1, 0) = 1"
            else:
                return f"multiIf({col_expr} = '', 0, isNull(IPv4StringToNumOrNull({col_expr})), 0, isIPAddressInRange({col_expr}, '{safe_value}'), 1, 0) = 1"

        # Handle severity as integer
        if field == 'severity':
            try:
                int_val = int(value)
                return f"severity {not_op} {int_val}"
            except ValueError:
                pass

        # Standard string comparison (case-insensitive)
        if negated:
            return f"lower({col_expr}) != lower('{safe_value}')"
        else:
            return f"lower({col_expr}) = lower('{safe_value}')"

    @classmethod
    def _build_where_clause(
        cls,
        device_ips: Optional[List[str]] = None,
        severities: Optional[List[int]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        facilities: Optional[List[int]] = None
    ) -> str:
        """Build WHERE clause for log queries with advanced search support."""
        where_clauses = ["1=1"]

        if device_ips:
            # Use toIPv4() for efficient index usage instead of toString()
            formatted_ips = ", ".join([f"toIPv4('{ip}')" for ip in device_ips])
            where_clauses.append(f"device_ip IN ({formatted_ips})")

        if severities:
            formatted_severities = ", ".join(map(str, severities))
            where_clauses.append(f"severity IN ({formatted_severities})")

        if facilities:
            formatted_facilities = ", ".join(map(str, facilities))
            where_clauses.append(f"facility IN ({formatted_facilities})")

        if start_time:
            where_clauses.append(f"timestamp >= '{start_time.isoformat()}'")

        if end_time:
            where_clauses.append(f"timestamp <= '{end_time.isoformat()}'")

        if query_text:
            terms = cls._parse_advanced_query(query_text)

            if terms:
                for term in terms:
                    if term['type'] == 'field':
                        condition = cls._build_field_condition(
                            term['field'],
                            term['value'],
                            term['negated']
                        )
                        where_clauses.append(condition)
                    else:
                        safe_value = term['value'].replace("'", "''")
                        if term['negated']:
                            where_clauses.append(
                                f"NOT (message ILIKE '%{safe_value}%' OR raw ILIKE '%{safe_value}%')"
                            )
                        else:
                            where_clauses.append(
                                f"(message ILIKE '%{safe_value}%' OR raw ILIKE '%{safe_value}%')"
                            )
            else:
                safe_query = query_text.replace("'", "''")
                where_clauses.append(f"(message ILIKE '%{safe_query}%' OR raw ILIKE '%{safe_query}%')")

        return " AND ".join(where_clauses)

    @classmethod
    def search_logs(
        cls,
        limit: int = 100,
        offset: int = 0,
        device_ips: Optional[List[str]] = None,
        severities: Optional[List[int]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        facilities: Optional[List[int]] = None,
        default_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Search logs with advanced filtering. Defaults to last 24 hours for performance."""
        client = cls.get_client()

        # Apply default time filter if no time range specified
        if start_time is None and end_time is None:
            where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)
            time_filter = f"timestamp > now() - INTERVAL {default_hours} HOUR"
            if where_sql != "1=1":
                where_sql = f"{time_filter} AND {where_sql}"
            else:
                where_sql = time_filter
        else:
            where_sql = cls._build_where_clause(device_ips, severities, start_time, end_time, query_text, facilities)

        query = f"""
        SELECT timestamp, device_ip, facility, severity, message, raw, parsed_data
        FROM syslogs
        WHERE {where_sql}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """

        result = client.query(query).named_results()
        return list(result)

    @classmethod
    def count_logs(
        cls,
        device_ips: Optional[List[str]] = None,
        severities: Optional[List[int]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        facilities: Optional[List[int]] = None,
        default_hours: int = 24
    ) -> int:
        """Count logs matching filters. Defaults to last 24 hours for performance."""
        client = cls.get_client()

        # Apply default time filter if no time range specified
        if start_time is None and end_time is None:
            where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)
            time_filter = f"timestamp > now() - INTERVAL {default_hours} HOUR"
            if where_sql != "1=1":
                where_sql = f"{time_filter} AND {where_sql}"
            else:
                where_sql = time_filter
        else:
            where_sql = cls._build_where_clause(device_ips, severities, start_time, end_time, query_text, facilities)

        query = f"""
        SELECT count() as total
        FROM syslogs
        WHERE {where_sql}
        """

        result = client.query(query).result_rows
        return result[0][0] if result else 0

    @classmethod
    def get_log_stats_summary(
        cls,
        device_ips: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        default_hours: int = 24
    ) -> Dict[str, Any]:
        """Get summary statistics for logs matching the current filters."""
        client = cls.get_client()

        # If no time filter specified, default to last 24 hours for performance
        if start_time is None and end_time is None:
            where_sql = cls._build_where_clause(device_ips, None, None, None, query_text, None)
            time_filter = f"timestamp > now() - INTERVAL {default_hours} HOUR"
            if where_sql != "1=1":
                where_sql = f"{time_filter} AND {where_sql}"
            else:
                where_sql = time_filter
        else:
            where_sql = cls._build_where_clause(device_ips, None, start_time, end_time, query_text, None)

        query = f"""
        SELECT
            count() as total_logs,
            uniq(device_ip) as unique_devices,
            countIf(severity <= 3) as critical_count,
            countIf(severity = 4) as warning_count,
            countIf(severity >= 5) as info_count
        FROM syslogs
        WHERE {where_sql}
        """

        result = list(client.query(query).named_results())
        return result[0] if result else {}

    @classmethod
    def get_severity_distribution(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """Get severity distribution for charts."""
        client = cls.get_client()

        query = f"""
        SELECT severity, count() as count
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY severity
        ORDER BY severity
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_device_log_counts(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """Get log counts per device."""
        client = cls.get_client()

        query = f"""
        SELECT
            toString(device_ip) as device_ip,
            count() as count,
            max(timestamp) as last_log
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY device_ip
        ORDER BY count DESC
        LIMIT 20
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_distinct_devices(cls, hours: int = 1) -> List[str]:
        """
        Get list of distinct device IPs from recent logs.

        Default: last 1 hour (fast) - devices sending logs are typically always active.
        Falls back to 24h if no devices found in 1h window.
        """
        client = cls.get_client()
        # First try short window for speed
        query = f"""
        SELECT DISTINCT toString(device_ip) as device_ip
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        ORDER BY device_ip
        """
        result = [row[0] for row in client.query(query).result_rows]

        # If no devices found in short window, expand to 24h
        if not result and hours < 24:
            query = """
            SELECT DISTINCT toString(device_ip) as device_ip
            FROM syslogs
            WHERE timestamp > now() - INTERVAL 24 HOUR
            ORDER BY device_ip
            """
            result = [row[0] for row in client.query(query).result_rows]

        return result

    @classmethod
    def get_storage_stats(cls) -> Dict[str, Any]:
        """Get overall storage statistics for the syslogs table."""
        client = cls.get_client()

        query = """
        SELECT
            formatReadableSize(sum(data_compressed_bytes)) as compressed_size,
            formatReadableSize(sum(data_uncompressed_bytes)) as uncompressed_size,
            sum(rows) as total_rows,
            round(sum(data_uncompressed_bytes) / sum(data_compressed_bytes), 2) as compression_ratio,
            sum(data_compressed_bytes) as compressed_bytes,
            sum(data_uncompressed_bytes) as uncompressed_bytes
        FROM system.parts
        WHERE table = 'syslogs' AND active = 1
        """

        result = list(client.query(query).named_results())
        if result and result[0]['total_rows']:
            return result[0]
        return {
            'compressed_size': '0 B',
            'uncompressed_size': '0 B',
            'total_rows': 0,
            'compression_ratio': 0,
            'compressed_bytes': 0,
            'uncompressed_bytes': 0
        }

    @classmethod
    def get_per_device_storage(cls) -> List[Dict[str, Any]]:
        """Get storage usage breakdown per device."""
        client = cls.get_client()

        query = """
        SELECT
            toString(device_ip) as device_ip,
            count() as log_count,
            min(timestamp) as oldest_log,
            max(timestamp) as newest_log,
            avg(length(raw)) as avg_raw_size,
            sum(length(raw)) as total_raw_size
        FROM syslogs
        GROUP BY device_ip
        ORDER BY log_count DESC
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_storage_by_time_range(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """Get storage distribution over time for visualization."""
        client = cls.get_client()

        query = f"""
        SELECT
            toStartOfHour(timestamp) as hour,
            count() as log_count,
            sum(length(raw)) as raw_bytes
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY hour
        ORDER BY hour
        """

        return list(client.query(query).named_results())

    @classmethod
    def delete_old_logs_for_device(cls, device_ip: str, retention_days: int) -> bool:
        """Delete logs older than retention_days for a specific device."""
        if retention_days <= 0:
            return False  # No deletion for unlimited retention

        client = cls.get_client()

        query = f"""
        ALTER TABLE syslogs DELETE
        WHERE device_ip = toIPv4('{device_ip}')
        AND timestamp < now() - INTERVAL {retention_days} DAY
        """

        try:
            client.command(query)
            logger.info(f"Scheduled deletion of logs older than {retention_days} days for device {device_ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete old logs for {device_ip}: {e}")
            return False

    @classmethod
    def get_device_log_age_distribution(cls, device_ip: str) -> Dict[str, Any]:
        """Get age distribution of logs for a specific device."""
        client = cls.get_client()

        query = f"""
        SELECT
            countIf(timestamp > now() - INTERVAL 1 DAY) as last_24h,
            countIf(timestamp > now() - INTERVAL 7 DAY AND timestamp <= now() - INTERVAL 1 DAY) as last_week,
            countIf(timestamp > now() - INTERVAL 30 DAY AND timestamp <= now() - INTERVAL 7 DAY) as last_month,
            countIf(timestamp <= now() - INTERVAL 30 DAY) as older,
            count() as total
        FROM syslogs
        WHERE device_ip = toIPv4('{device_ip}')
        """

        result = list(client.query(query).named_results())
        return result[0] if result else {'last_24h': 0, 'last_week': 0, 'last_month': 0, 'older': 0, 'total': 0}

    @classmethod
    def get_traffic_timeline(cls, hours: int = 1) -> List[Dict[str, Any]]:
        """Get traffic timeline for dashboard chart."""
        client = cls.get_client()

        query = f"""
        SELECT
            toStartOfMinute(timestamp) as minute,
            count() as count
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY minute
        ORDER BY minute
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_total_logs_24h(cls) -> int:
        """Get total log count in last 24 hours."""
        client = cls.get_client()
        query = "SELECT count() FROM syslogs WHERE timestamp > now() - INTERVAL 24 HOUR"
        result = client.query(query).result_rows
        return result[0][0] if result else 0

    @classmethod
    def get_unique_devices_count(cls) -> int:
        """Get count of unique devices."""
        client = cls.get_client()
        query = "SELECT uniq(device_ip) FROM syslogs"
        result = client.query(query).result_rows
        return result[0][0] if result else 0

    @classmethod
    def get_session_flow(
        cls,
        srcip: str,
        dstip: str,
        dstport: str,
        proto: str,
        timestamp: datetime,
        time_window_seconds: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find all firewall logs related to a session across multiple firewalls.

        This correlates logs based on the 5-tuple (srcip, dstip, dstport, proto)
        within a time window to show the packet flow across all firewalls.

        Args:
            srcip: Source IP address
            dstip: Destination IP address
            dstport: Destination port
            proto: Protocol number (6=TCP, 17=UDP, 1=ICMP)
            timestamp: Reference timestamp for the session
            time_window_seconds: Time window to search (default ±10 seconds)

        Returns:
            List of log entries from all firewalls that handled this session,
            ordered by timestamp to show the flow path.
        """
        client = cls.get_client()

        # Escape values for SQL
        safe_srcip = srcip.replace("'", "''")
        safe_dstip = dstip.replace("'", "''")
        safe_dstport = dstport.replace("'", "''")
        safe_proto = proto.replace("'", "''")

        # Build time range
        ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

        query = f"""
        SELECT
            timestamp,
            toString(device_ip) as device_ip,
            severity,
            parsed_data,
            parsed_data['action'] as action,
            parsed_data['srcip'] as srcip,
            parsed_data['dstip'] as dstip,
            parsed_data['srcport'] as srcport,
            parsed_data['dstport'] as dstport,
            parsed_data['proto'] as proto,
            parsed_data['srcintf'] as srcintf,
            parsed_data['dstintf'] as dstintf,
            parsed_data['policyid'] as policyid,
            parsed_data['policyname'] as policyname,
            parsed_data['service'] as service,
            parsed_data['duration'] as duration,
            parsed_data['sentbyte'] as sentbyte,
            parsed_data['rcvdbyte'] as rcvdbyte
        FROM syslogs
        WHERE
            parsed_data['srcip'] = '{safe_srcip}'
            AND parsed_data['dstip'] = '{safe_dstip}'
            AND parsed_data['dstport'] = '{safe_dstport}'
            AND parsed_data['proto'] = '{safe_proto}'
            AND timestamp BETWEEN
                toDateTime64('{ts_str}', 3) - INTERVAL {time_window_seconds} SECOND
                AND toDateTime64('{ts_str}', 3) + INTERVAL {time_window_seconds} SECOND
        ORDER BY timestamp ASC
        """

        result = list(client.query(query).named_results())
        return result

    @classmethod
    def get_session_flow_by_log(
        cls,
        log_timestamp: str,
        device_ip: str,
        time_window_seconds: int = 10
    ) -> Dict[str, Any]:
        """
        Get session flow starting from a specific log entry.

        First retrieves the log to get session details, then finds all related
        logs across firewalls.

        Args:
            log_timestamp: ISO format timestamp of the log entry
            device_ip: Device IP that logged the entry
            time_window_seconds: Time window to search for related logs

        Returns:
            Dictionary with:
            - original_log: The original log entry
            - flow: List of all related logs across firewalls
            - summary: Flow summary (total firewalls, all allowed, path)
        """
        client = cls.get_client()

        # First get the original log
        safe_device = device_ip.replace("'", "''")

        query = f"""
        SELECT
            timestamp,
            toString(device_ip) as device_ip,
            severity,
            parsed_data
        FROM syslogs
        WHERE
            device_ip = toIPv4('{safe_device}')
            AND timestamp = toDateTime64('{log_timestamp}', 3)
        LIMIT 1
        """

        original = list(client.query(query).named_results())
        if not original:
            return {'original_log': None, 'flow': [], 'summary': {}}

        original_log = original[0]
        pd = original_log.get('parsed_data', {})

        srcip = pd.get('srcip', '')
        dstip = pd.get('dstip', '')
        dstport = pd.get('dstport', '')
        proto = pd.get('proto', '')

        if not all([srcip, dstip, dstport, proto]):
            return {
                'original_log': original_log,
                'flow': [original_log],
                'summary': {
                    'firewall_count': 1,
                    'all_allowed': pd.get('action', '').lower() not in ['deny', 'drop', 'block', 'reject'],
                    'has_deny': pd.get('action', '').lower() in ['deny', 'drop', 'block', 'reject']
                }
            }

        # Get all related logs
        flow = cls.get_session_flow(
            srcip=srcip,
            dstip=dstip,
            dstport=dstport,
            proto=proto,
            timestamp=original_log['timestamp'],
            time_window_seconds=time_window_seconds
        )

        # Build summary
        unique_firewalls = set(log['device_ip'] for log in flow)
        actions = [log.get('action', '').lower() for log in flow]
        has_deny = any(a in ['deny', 'drop', 'block', 'reject'] for a in actions)
        all_allowed = all(a not in ['deny', 'drop', 'block', 'reject'] for a in actions if a)

        return {
            'original_log': original_log,
            'flow': flow,
            'summary': {
                'firewall_count': len(unique_firewalls),
                'firewalls': list(unique_firewalls),
                'all_allowed': all_allowed,
                'has_deny': has_deny,
                'total_hops': len(flow)
            }
        }
