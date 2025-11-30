import clickhouse_connect
from django.conf import settings
import logging

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

    @classmethod
    def get_client(cls):
        """Create a new client instance for thread safety."""
        try:
            return clickhouse_connect.get_client(
                host=settings.CLICKHOUSE_HOST,
                port=settings.CLICKHOUSE_PORT,
                username=settings.CLICKHOUSE_USER,
                password=settings.CLICKHOUSE_PASSWORD,
                database=settings.CLICKHOUSE_DB,
                # Performance settings
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
    def ensure_table(cls):
        """
        Create optimized table schema for high-volume log ingestion.

        Optimizations:
        - PARTITION BY toYYYYMM: Monthly partitions for efficient data lifecycle
        - ORDER BY (device_ip, timestamp): Optimized for device-based queries
        - LZ4 compression: Fast compression for high-throughput ingestion
        - TTL: Automatic data expiration after 3 months
        - ReplacingMergeTree alternative for dedup if needed
        """
        client = cls.get_client()

        # Optimized table schema for production
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
            # Table might exist with old schema, try migration
            logger.warning(f"Table creation issue (may already exist): {e}")
            cls._migrate_table()

    @classmethod
    def _migrate_table(cls):
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
    def insert_logs(cls, logs):
        """
        logs: List of tuples/lists matching the schema columns
        (timestamp, device_ip, facility, severity, message, raw, parsed_data)
        """
        if not logs:
            return
        client = cls.get_client()
        client.insert('syslogs', logs, column_names=[
            'timestamp', 'device_ip', 'facility', 'severity', 'message', 'raw', 'parsed_data'
        ])

    @classmethod
    def get_recent_logs(cls, limit=100):
        client = cls.get_client()
        query = "SELECT timestamp, device_ip, severity, message FROM syslogs ORDER BY timestamp DESC LIMIT %(limit)d"
        result = client.query(query, parameters={'limit': limit})
        return result.named_results()

    @classmethod
    def get_stats(cls):
        client = cls.get_client()
        
        # Severity counts (last 24h)
        severity_query = """
        SELECT severity, count() 
        FROM syslogs 
        WHERE timestamp > now() - INTERVAL 24 HOUR 
        GROUP BY severity
        """
        severity_data = client.query(severity_query).result_rows
        
        # Logs per minute (last 1h)
        traffic_query = """
        SELECT toStartOfMinute(timestamp) as t, count() 
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
    def _parse_advanced_query(cls, query_text):
        """
        Parse advanced search query with field:value syntax, negation, and CIDR support.

        Supported formats:
        - srcip:192.168.1.1       (exact field match)
        - -srcip:192.168.1.1      (negated field match)
        - srcip:192.168.0.0/24    (CIDR subnet match)
        - "connection timeout"     (text search in message/raw)
        - timeout                  (text search in message/raw)
        """
        import re

        terms = []
        # Regex to parse field:value pairs and plain text
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
    def _is_cidr(cls, value):
        """Check if value is CIDR notation."""
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value))

    @classmethod
    def _build_field_condition(cls, field, value, negated=False):
        """Build SQL condition for a specific field."""
        # Escape single quotes
        safe_value = value.replace("'", "''")
        op = "NOT " if negated else ""
        not_op = "!=" if negated else "="

        # Map frontend field names to parsed_data keys or column names
        # Supports both Fortinet and Palo Alto field names (normalized)
        field_mapping = {
            # Common normalized fields (work across vendors)
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
            # Fortinet-specific fields
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
            'policyname': "parsed_data['policyname']",
            'srccountry': "parsed_data['srccountry']",
            'dstcountry': "parsed_data['dstcountry']",
            'appcat': "parsed_data['appcat']",
            'user': "parsed_data['user']",
            # Palo Alto-specific fields (original names)
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

        # Get the actual column/expression
        col_expr = field_mapping.get(field)
        if not col_expr:
            # Unknown field - search in parsed_data with dynamic key
            col_expr = f"parsed_data['{field}']"

        # Handle CIDR notation for IP fields
        if field in ('srcip', 'dstip') and cls._is_cidr(value):
            # Use ClickHouse's isIPAddressInRange function with proper null/empty handling
            # Use multiIf to short-circuit evaluation and avoid parsing empty strings as IPs
            # Also validate IP format with IPv4StringToNumOrNull before calling isIPAddressInRange
            if negated:
                # NOT in range: return true if empty OR if valid IP is not in range
                return f"multiIf({col_expr} = '', 1, isNull(IPv4StringToNumOrNull({col_expr})), 1, NOT isIPAddressInRange({col_expr}, '{safe_value}'), 1, 0) = 1"
            else:
                # IN range: return true only if non-empty AND valid IP AND in range
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
    def _build_where_clause(cls, device_ips=None, severities=None, start_time=None, end_time=None, query_text=None, facilities=None):
        """Build WHERE clause for log queries with advanced search support."""
        where_clauses = ["1=1"]

        if device_ips:
            formatted_ips = "', '".join(device_ips)
            where_clauses.append(f"toString(device_ip) IN ('{formatted_ips}')")

        if severities:
            formatted_severities = ", ".join(map(str, severities))
            where_clauses.append(f"severity IN ({formatted_severities})")

        if facilities:
            formatted_facilities = ", ".join(map(str, facilities))
            where_clauses.append(f"facility IN ({formatted_facilities})")

        if start_time:
            where_clauses.append(f"timestamp >= '{start_time}'")

        if end_time:
            where_clauses.append(f"timestamp <= '{end_time}'")

        if query_text:
            # Parse advanced query syntax
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
                        # Plain text search in message and raw fields
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
                # Fallback to simple text search if no terms parsed
                safe_query = query_text.replace("'", "''")
                where_clauses.append(f"(message ILIKE '%{safe_query}%' OR raw ILIKE '%{safe_query}%')")

        return " AND ".join(where_clauses)

    @classmethod
    def search_logs(cls, limit=100, offset=0, device_ips=None, severities=None, start_time=None, end_time=None, query_text=None, facilities=None):
        """Search logs with advanced filtering."""
        client = cls.get_client()
        where_sql = cls._build_where_clause(device_ips, severities, start_time, end_time, query_text, facilities)

        query = f"""
        SELECT timestamp, device_ip, facility, severity, message, raw, parsed_data
        FROM syslogs
        WHERE {where_sql}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
        """

        result = client.query(query).named_results()
        return result

    @classmethod
    def count_logs(cls, device_ips=None, severities=None, start_time=None, end_time=None, query_text=None, facilities=None):
        """Count logs matching filters."""
        client = cls.get_client()
        where_sql = cls._build_where_clause(device_ips, severities, start_time, end_time, query_text, facilities)

        query = f"""
        SELECT count() as total
        FROM syslogs
        WHERE {where_sql}
        """

        result = client.query(query).result_rows
        return result[0][0] if result else 0

    @classmethod
    def get_log_stats_summary(cls, device_ips=None, start_time=None, end_time=None, query_text=None):
        """Get summary statistics for logs matching the current filters."""
        client = cls.get_client()
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
    def get_severity_distribution(cls, hours=24):
        """Get severity distribution for charts."""
        client = cls.get_client()

        query = f"""
        SELECT severity, count() as count
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY severity
        ORDER BY severity
        """

        return client.query(query).named_results()

    @classmethod
    def get_device_log_counts(cls, hours=24):
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

        return client.query(query).named_results()

    @classmethod
    def get_distinct_devices(cls):
        client = cls.get_client()
        query = "SELECT DISTINCT toString(device_ip) as device_ip FROM syslogs ORDER BY device_ip"
        return [row[0] for row in client.query(query).result_rows]

    @classmethod
    def get_storage_stats(cls):
        """
        Get overall storage statistics for the syslogs table.
        Returns total rows, compressed size, uncompressed size, and compression ratio.
        """
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
    def get_per_device_storage(cls):
        """
        Get storage usage breakdown per device.
        Returns list of devices with their log counts and estimated storage.
        """
        client = cls.get_client()

        # Get per-device stats: count, oldest log, newest log, avg message size
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
    def get_storage_by_time_range(cls, hours=24):
        """
        Get storage distribution over time for visualization.
        """
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
    def delete_old_logs_for_device(cls, device_ip, retention_days):
        """
        Delete logs older than retention_days for a specific device.
        Returns the number of rows affected.
        """
        if retention_days <= 0:
            return 0  # No deletion for unlimited retention

        client = cls.get_client()

        # Use ALTER TABLE DELETE for ClickHouse
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
    def get_device_log_age_distribution(cls, device_ip):
        """
        Get age distribution of logs for a specific device.
        Returns counts by age buckets (last 24h, last week, last month, older).
        """
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
