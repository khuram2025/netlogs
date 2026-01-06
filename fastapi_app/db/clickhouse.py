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

            -- Dedicated columns for key parsed fields (inserted directly)
            srcip String DEFAULT '' CODEC(ZSTD(1)),
            dstip String DEFAULT '' CODEC(ZSTD(1)),
            srcport UInt16 DEFAULT 0 CODEC(T64, LZ4),
            dstport UInt16 DEFAULT 0 CODEC(T64, LZ4),
            proto UInt8 DEFAULT 0 CODEC(T64, LZ4),
            action LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),

            -- Keep parsed_data Map for all other fields
            parsed_data Map(String, String) CODEC(ZSTD(1)),

            -- Materialized columns for common queries
            log_date Date MATERIALIZED toDate(timestamp),
            log_hour UInt8 MATERIALIZED toHour(timestamp),

            -- Indexes for common queries
            INDEX idx_severity severity TYPE minmax GRANULARITY 4,
            INDEX idx_srcip srcip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dstip dstip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_srcport srcport TYPE minmax GRANULARITY 4,
            INDEX idx_dstport dstport TYPE minmax GRANULARITY 4,
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
        """Migrate existing table to add new columns and indexes."""
        client = cls.get_client()
        migrations = [
            # Add dedicated columns for key parsed fields
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS srcip String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS dstip String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS srcport UInt16 DEFAULT 0 CODEC(T64, LZ4)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS dstport UInt16 DEFAULT 0 CODEC(T64, LZ4)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS proto UInt8 DEFAULT 0 CODEC(T64, LZ4)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS action String DEFAULT '' CODEC(ZSTD(1))",
            # Keep parsed_data for other fields
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS parsed_data Map(String, String) CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_date Date MATERIALIZED toDate(timestamp)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_hour UInt8 MATERIALIZED toHour(timestamp)",
            # Add indexes
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_srcip srcip TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_dstip dstip TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_srcport srcport TYPE minmax GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_dstport dstport TYPE minmax GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_action action TYPE bloom_filter(0.01) GRANULARITY 4",
        ]
        for migration in migrations:
            try:
                client.command(migration)
            except Exception as e:
                logger.debug(f"Migration skipped: {e}")

    @classmethod
    def backfill_ip_columns(cls) -> Dict[str, Any]:
        """
        Backfill srcip and dstip columns from parsed_data for existing records.

        This is a one-time migration to populate the indexed IP columns
        for records that were inserted before the optimization.

        Returns status dict with rows_updated count.
        """
        client = cls.get_client()

        # Check how many rows need updating
        check_query = """
        SELECT count() as empty_srcip
        FROM syslogs
        WHERE srcip = '' AND (parsed_data['srcip'] != '' OR parsed_data['src_ip'] != '')
        """
        result = client.query(check_query).result_rows
        empty_count = result[0][0] if result else 0

        if empty_count == 0:
            return {'status': 'complete', 'rows_updated': 0, 'message': 'No rows need backfilling'}

        # Backfill srcip column
        srcip_query = """
        ALTER TABLE syslogs
        UPDATE srcip = if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip'])
        WHERE srcip = '' AND (parsed_data['srcip'] != '' OR parsed_data['src_ip'] != '')
        """

        # Backfill dstip column
        dstip_query = """
        ALTER TABLE syslogs
        UPDATE dstip = if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip'])
        WHERE dstip = '' AND (parsed_data['dstip'] != '' OR parsed_data['dst_ip'] != '')
        """

        try:
            logger.info(f"Starting backfill for approximately {empty_count:,} rows...")
            client.command(srcip_query)
            client.command(dstip_query)
            logger.info("Backfill mutations scheduled. Run 'SELECT * FROM system.mutations WHERE is_done = 0' to check status.")
            return {
                'status': 'scheduled',
                'rows_to_update': empty_count,
                'message': 'Backfill mutations scheduled. ClickHouse will process them asynchronously.'
            }
        except Exception as e:
            logger.error(f"Backfill failed: {e}")
            return {'status': 'error', 'message': str(e)}

    @classmethod
    def insert_logs(cls, logs: List[Tuple]) -> None:
        """
        Insert logs in batch.

        Args:
            logs: List of tuples matching the schema columns
                  (timestamp, device_ip, facility, severity, message, raw,
                   srcip, dstip, srcport, dstport, proto, action, parsed_data)

        Note: srcip and dstip are now populated for fast indexed queries.
              They have bloom filter indexes for efficient filtering.
        """
        if not logs:
            return
        client = cls.get_client()

        # Include srcip and dstip for indexed queries (bloom filter)
        # Input:  (timestamp, device_ip, facility, severity, message, raw, srcip, dstip, srcport, dstport, proto, action, parsed_data)
        # Output: (timestamp, device_ip, facility, severity, message, raw, srcip, dstip, srcport, dstport, proto, action, parsed_data)
        client.insert('syslogs', logs, column_names=[
            'timestamp', 'device_ip', 'facility', 'severity', 'message', 'raw',
            'srcip', 'dstip', 'srcport', 'dstport', 'proto', 'action', 'parsed_data'
        ])

    @classmethod
    def get_recent_logs(cls, limit: int = 100) -> List[Dict[str, Any]]:
        """Get most recent logs."""
        client = cls.get_client()
        query = f"""
        SELECT timestamp, device_ip, facility, severity, message, raw,
               srcip, dstip, srcport, dstport, proto, action, parsed_data
        FROM syslogs ORDER BY timestamp DESC LIMIT {limit}
        """
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
        Parse advanced search query with field:operator:value syntax.

        Supported formats:
        - srcip:192.168.1.1           (exact field match, operator = '=')
        - srcip:=192.168.1.1          (explicit equals)
        - srcip:!=192.168.1.1         (not equals)
        - -srcip:192.168.1.1          (negated, same as !=)
        - dstport:>1024               (greater than)
        - dstport:>=80                (greater than or equal)
        - dstport:<1024               (less than)
        - dstport:<=443               (less than or equal)
        - srcip:192.168.0.0/24        (CIDR subnet match)
        - srcip:192.168.1.1-192.168.1.50  (IP range)
        - srcip:192.168.*.*           (wildcard)
        - srcip:10.1.1.1,8.8.8.8      (multiple comma-separated IPs)
        - dstip:192.168.0.0/24,10.0.0.1  (mixed: CIDR + IP)
        - srcip:10.1.1.1,192.168.1.0/24,8.8.8.8  (multiple mixed formats)
        - message:~error              (contains/like)
        - message:~*timeout*          (wildcard contains)
        - action:accept|allow|close   (OR multiple values)
        - "connection timeout"        (text search in message/raw)
        - timeout                     (text search in message/raw)
        """
        terms = []

        # Pattern to match field:operator:value or field:value
        # Supports operators: =, !=, >, >=, <, <=, ~
        pattern = r'(-?)(\w+):(!=|>=|<=|>|<|=|~)?("[^"]+"|[^\s]+)|(-?)("[^"]+"|[^\s]+)'

        for match in re.finditer(pattern, query_text):
            if match.group(2):  # field:value format
                negated = match.group(1) == '-'
                field = match.group(2).lower()
                operator = match.group(3) or '='
                value = match.group(4).strip('"') if match.group(4) else ''

                # Handle != as negation
                if operator == '!=':
                    negated = True
                    operator = '='

                terms.append({
                    'type': 'field',
                    'field': field,
                    'value': value,
                    'operator': operator,
                    'negated': negated
                })
            elif match.group(6):  # plain text
                negated = match.group(5) == '-'
                value = match.group(6).strip('"')
                terms.append({
                    'type': 'text',
                    'value': value,
                    'negated': negated
                })

        return terms

    @classmethod
    def _is_multi_ip(cls, value: str) -> bool:
        """Check if value contains multiple comma-separated IPs or ranges."""
        return ',' in value

    @classmethod
    def _is_cidr(cls, value: str) -> bool:
        """Check if value is CIDR notation."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value))

    @classmethod
    def _is_ip_range(cls, value: str) -> bool:
        """Check if value is an IP range (e.g., 192.168.1.1-192.168.1.50)."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))

    @classmethod
    def _is_wildcard_ip(cls, value: str) -> bool:
        """Check if value is a wildcard IP (e.g., 192.168.1.* or 192.168.*.*)."""
        return '*' in value and re.match(r'^[\d\.\*]+$', value)

    @classmethod
    def _build_field_condition(cls, field: str, value: str, negated: bool = False, operator: str = '=') -> str:
        """
        Build SQL condition for a specific field with operator support.

        Operators:
        - '=' : equals (default)
        - '>' : greater than
        - '>=' : greater than or equal
        - '<' : less than
        - '<=' : less than or equal
        - '~' : contains/like
        """
        safe_value = value.replace("'", "''")
        not_prefix = "NOT " if negated else ""

        # OPTIMIZATION: Use indexed srcip/dstip columns directly for ALL IP operations
        # These columns have bloom filter indexes for fast filtering
        ip_fields_indexed = ('srcip', 'dstip')

        if field in ip_fields_indexed and operator == '=':
            # Use the indexed column directly for all IP operations
            col = field  # Direct column access (srcip or dstip)

            # Handle CIDR notation (e.g., 192.168.0.0/24)
            if cls._is_cidr(value):
                ip_part, mask = value.rsplit('/', 1)
                mask_int = int(mask)
                octets = ip_part.split('.')

                # For /8, /16, /24 use fast LIKE prefix matching
                if mask_int == 8 and len(octets) >= 1:
                    prefix = f"{octets[0]}."
                    if negated:
                        return f"NOT startsWith({col}, '{prefix}')"
                    return f"startsWith({col}, '{prefix}')"
                elif mask_int == 16 and len(octets) >= 2:
                    prefix = f"{octets[0]}.{octets[1]}."
                    if negated:
                        return f"NOT startsWith({col}, '{prefix}')"
                    return f"startsWith({col}, '{prefix}')"
                elif mask_int == 24 and len(octets) >= 3:
                    prefix = f"{octets[0]}.{octets[1]}.{octets[2]}."
                    if negated:
                        return f"NOT startsWith({col}, '{prefix}')"
                    return f"startsWith({col}, '{prefix}')"
                else:
                    # For other masks, use IPv4 range comparison
                    if negated:
                        return f"({col} = '' OR NOT isIPAddressInRange({col}, '{safe_value}'))"
                    return f"({col} != '' AND isIPAddressInRange({col}, '{safe_value}'))"

            # Handle IP range (e.g., 192.168.1.1-192.168.1.50)
            if cls._is_ip_range(value):
                start_ip, end_ip = value.split('-')
                safe_start = start_ip.replace("'", "''")
                safe_end = end_ip.replace("'", "''")
                condition = f"({col} != '' AND IPv4StringToNumOrNull({col}) >= IPv4StringToNumOrNull('{safe_start}') AND IPv4StringToNumOrNull({col}) <= IPv4StringToNumOrNull('{safe_end}'))"
                if negated:
                    return f"NOT ({condition})"
                return condition

            # Handle wildcard IP (e.g., 192.168.1.*)
            if cls._is_wildcard_ip(value):
                prefix = value.split('*')[0]
                if negated:
                    return f"{col} NOT LIKE '{prefix}%'"
                return f"{col} LIKE '{prefix}%'"

            # Handle multiple comma-separated IPs/ranges/CIDR
            if cls._is_multi_ip(value):
                parts = [p.strip() for p in value.split(',') if p.strip()]
                conditions = []
                for part in parts:
                    safe_part = part.replace("'", "''")
                    if cls._is_cidr(part):
                        ip_part, mask = part.rsplit('/', 1)
                        mask_int = int(mask)
                        octets = ip_part.split('.')
                        if mask_int == 8:
                            conditions.append(f"startsWith({col}, '{octets[0]}.')")
                        elif mask_int == 16:
                            conditions.append(f"startsWith({col}, '{octets[0]}.{octets[1]}.')")
                        elif mask_int == 24:
                            conditions.append(f"startsWith({col}, '{octets[0]}.{octets[1]}.{octets[2]}.')")
                        else:
                            conditions.append(f"({col} != '' AND isIPAddressInRange({col}, '{safe_part}'))")
                    elif cls._is_ip_range(part):
                        start_ip, end_ip = part.split('-')
                        conditions.append(f"({col} != '' AND IPv4StringToNumOrNull({col}) >= IPv4StringToNumOrNull('{start_ip}') AND IPv4StringToNumOrNull({col}) <= IPv4StringToNumOrNull('{end_ip}'))")
                    elif cls._is_wildcard_ip(part):
                        prefix = part.split('*')[0]
                        conditions.append(f"{col} LIKE '{prefix}%'")
                    else:
                        conditions.append(f"{col} = '{safe_part}'")

                if conditions:
                    combined = f"({' OR '.join(conditions)})"
                    if negated:
                        return f"NOT {combined}"
                    return combined

            # Simple exact IP match
            if negated:
                return f"{col} != '{safe_value}'"
            return f"{col} = '{safe_value}'"

        # Field mapping for normalized and vendor-specific fields
        # Uses COALESCE to check both normalized (Fortinet-style) and Palo Alto fields
        field_mapping = {
            # Common normalized fields - check both normalized and PA original
            'srcip': "if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip'])",
            'dstip': "if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip'])",
            'srcport': "if(parsed_data['srcport'] != '', parsed_data['srcport'], parsed_data['src_port'])",
            'dstport': "if(parsed_data['dstport'] != '', parsed_data['dstport'], parsed_data['dst_port'])",
            'action': "if(action != '', action, parsed_data['action'])",
            'proto': "if(parsed_data['proto'] != '', parsed_data['proto'], parsed_data['protocol'])",
            'app': "if(parsed_data['app'] != '', parsed_data['app'], parsed_data['application'])",
            'srcintf': "if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if'])",
            'dstintf': "if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if'])",
            'srczone': "if(parsed_data['srczone'] != '', parsed_data['srczone'], parsed_data['src_zone'])",
            'dstzone': "if(parsed_data['dstzone'] != '', parsed_data['dstzone'], parsed_data['dst_zone'])",
            'srcuser': "if(parsed_data['srcuser'] != '', parsed_data['srcuser'], parsed_data['src_user'])",
            'dstuser': "if(parsed_data['dstuser'] != '', parsed_data['dstuser'], parsed_data['dst_user'])",
            'sessionid': "if(parsed_data['sessionid'] != '', parsed_data['sessionid'], parsed_data['session_id'])",
            'duration': "if(parsed_data['duration'] != '', parsed_data['duration'], parsed_data['elapsed_time'])",
            'sentbyte': "if(parsed_data['sentbyte'] != '', parsed_data['sentbyte'], parsed_data['bytes_sent'])",
            'rcvdbyte': "if(parsed_data['rcvdbyte'] != '', parsed_data['rcvdbyte'], parsed_data['bytes_recv'])",
            'srccountry': "if(parsed_data['srccountry'] != '', parsed_data['srccountry'], parsed_data['src_location'])",
            'dstcountry': "if(parsed_data['dstcountry'] != '', parsed_data['dstcountry'], parsed_data['dst_location'])",
            # Fortinet-specific
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
            'policyname': "if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule'])",
            'appcat': "if(parsed_data['appcat'] != '', parsed_data['appcat'], parsed_data['category_of_app'])",
            'user': "parsed_data['user']",
            # Palo Alto-specific (original field names)
            'src_ip': "if(parsed_data['src_ip'] != '', parsed_data['src_ip'], parsed_data['srcip'])",
            'dst_ip': "if(parsed_data['dst_ip'] != '', parsed_data['dst_ip'], parsed_data['dstip'])",
            'src_port': "if(parsed_data['src_port'] != '', parsed_data['src_port'], parsed_data['srcport'])",
            'dst_port': "if(parsed_data['dst_port'] != '', parsed_data['dst_port'], parsed_data['dstport'])",
            'src_zone': "if(parsed_data['src_zone'] != '', parsed_data['src_zone'], parsed_data['srczone'])",
            'dst_zone': "if(parsed_data['dst_zone'] != '', parsed_data['dst_zone'], parsed_data['dstzone'])",
            'src_user': "if(parsed_data['src_user'] != '', parsed_data['src_user'], parsed_data['srcuser'])",
            'dst_user': "if(parsed_data['dst_user'] != '', parsed_data['dst_user'], parsed_data['dstuser'])",
            'inbound_if': "if(parsed_data['inbound_if'] != '', parsed_data['inbound_if'], parsed_data['srcintf'])",
            'outbound_if': "if(parsed_data['outbound_if'] != '', parsed_data['outbound_if'], parsed_data['dstintf'])",
            'application': "if(parsed_data['application'] != '', parsed_data['application'], parsed_data['app'])",
            'rule': "if(parsed_data['rule'] != '', parsed_data['rule'], parsed_data['policyname'])",
            'serial': "parsed_data['serial']",
            'vsys': "parsed_data['vsys']",
            'device_name': "if(parsed_data['device_name'] != '', parsed_data['device_name'], parsed_data['devname'])",
            'session_id': "if(parsed_data['session_id'] != '', parsed_data['session_id'], parsed_data['sessionid'])",
            'threat_id': "parsed_data['threat_id']",
            'category': "parsed_data['category']",
            'log_type': "parsed_data['log_type']",
            'session_end_reason': "parsed_data['session_end_reason']",
            # NAT fields
            'nat_srcip': "if(parsed_data['nat_srcip'] != '', parsed_data['nat_srcip'], parsed_data['nat_src_ip'])",
            'nat_dstip': "if(parsed_data['nat_dstip'] != '', parsed_data['nat_dstip'], parsed_data['nat_dst_ip'])",
            'nat_src_ip': "if(parsed_data['nat_src_ip'] != '', parsed_data['nat_src_ip'], parsed_data['nat_srcip'])",
            'nat_dst_ip': "if(parsed_data['nat_dst_ip'] != '', parsed_data['nat_dst_ip'], parsed_data['nat_dstip'])",
            'src_location': "if(parsed_data['src_location'] != '', parsed_data['src_location'], parsed_data['srccountry'])",
            'dst_location': "if(parsed_data['dst_location'] != '', parsed_data['dst_location'], parsed_data['dstcountry'])",
            # Byte/packet fields with fallback
            'bytes_sent': "if(parsed_data['bytes_sent'] != '', parsed_data['bytes_sent'], parsed_data['sentbyte'])",
            'bytes_recv': "if(parsed_data['bytes_recv'] != '', parsed_data['bytes_recv'], parsed_data['rcvdbyte'])",
            'elapsed_time': "if(parsed_data['elapsed_time'] != '', parsed_data['elapsed_time'], parsed_data['duration'])",
            # Common fields
            'type': "parsed_data['type']",
            'subtype': "parsed_data['subtype']",
            'device': "toString(device_ip)",
            'severity': "severity",
        }

        col_expr = field_mapping.get(field, f"parsed_data['{field}']")
        ip_fields = ('srcip', 'dstip', 'nat_srcip', 'nat_dstip', 'src_ip', 'dst_ip', 'nat_src_ip', 'nat_dst_ip', 'device')

        # Handle CIDR notation for IP fields (e.g., 192.168.0.0/24)
        # Optimized: use LIKE prefix for /8, /16, /24 masks (much faster)
        if field in ip_fields and cls._is_cidr(value):
            ip_part, mask = value.rsplit('/', 1)
            mask_int = int(mask)
            octets = ip_part.split('.')

            # For /8, /16, /24 use fast LIKE prefix matching
            if mask_int == 8 and len(octets) >= 1:
                prefix = f"{octets[0]}."
                if negated:
                    return f"NOT startsWith({col_expr}, '{prefix}')"
                return f"startsWith({col_expr}, '{prefix}')"
            elif mask_int == 16 and len(octets) >= 2:
                prefix = f"{octets[0]}.{octets[1]}."
                if negated:
                    return f"NOT startsWith({col_expr}, '{prefix}')"
                return f"startsWith({col_expr}, '{prefix}')"
            elif mask_int == 24 and len(octets) >= 3:
                prefix = f"{octets[0]}.{octets[1]}.{octets[2]}."
                if negated:
                    return f"NOT startsWith({col_expr}, '{prefix}')"
                return f"startsWith({col_expr}, '{prefix}')"
            else:
                # For other masks, use IPv4 range comparison (still optimized)
                if negated:
                    return f"({col_expr} = '' OR NOT isIPAddressInRange({col_expr}, '{safe_value}'))"
                return f"({col_expr} != '' AND isIPAddressInRange({col_expr}, '{safe_value}'))"

        # Handle IP range (e.g., 192.168.1.1-192.168.1.50)
        if field in ip_fields and cls._is_ip_range(value):
            start_ip, end_ip = value.split('-')
            safe_start = start_ip.replace("'", "''")
            safe_end = end_ip.replace("'", "''")
            condition = f"multiIf({col_expr} = '', 0, isNull(IPv4StringToNumOrNull({col_expr})), 0, IPv4StringToNumOrNull({col_expr}) >= IPv4StringToNumOrNull('{safe_start}') AND IPv4StringToNumOrNull({col_expr}) <= IPv4StringToNumOrNull('{safe_end}'), 1, 0) = 1"
            if negated:
                return f"NOT ({condition})"
            return condition

        # Handle wildcard IP (e.g., 192.168.1.* or 10.*.*.*)
        if field in ip_fields and cls._is_wildcard_ip(value):
            # Convert wildcard to LIKE pattern
            like_pattern = value.replace('.', '\\.').replace('*', '%')
            # Also create a simpler pattern for prefix matching
            prefix = value.split('*')[0]
            if negated:
                return f"{col_expr} NOT LIKE '{prefix}%'"
            return f"{col_expr} LIKE '{prefix}%'"

        # Handle multiple comma-separated IPs/ranges/CIDR (e.g., 10.11.50.30,8.8.8.8 or 192.168.1.0/24,10.0.0.1)
        if field in ip_fields and cls._is_multi_ip(value):
            parts = [p.strip() for p in value.split(',') if p.strip()]
            conditions = []
            for part in parts:
                safe_part = part.replace("'", "''")
                if cls._is_cidr(part):
                    # Handle CIDR notation
                    ip_part, mask = part.rsplit('/', 1)
                    mask_int = int(mask)
                    octets = ip_part.split('.')
                    if mask_int == 8:
                        prefix = f"{octets[0]}."
                        conditions.append(f"startsWith({col_expr}, '{prefix}')")
                    elif mask_int == 16:
                        prefix = f"{octets[0]}.{octets[1]}."
                        conditions.append(f"startsWith({col_expr}, '{prefix}')")
                    elif mask_int == 24:
                        prefix = f"{octets[0]}.{octets[1]}.{octets[2]}."
                        conditions.append(f"startsWith({col_expr}, '{prefix}')")
                    else:
                        conditions.append(f"({col_expr} != '' AND isIPAddressInRange({col_expr}, '{safe_part}'))")
                elif cls._is_ip_range(part):
                    # Handle IP range (e.g., 192.168.1.1-192.168.1.50)
                    start_ip, end_ip = part.split('-')
                    safe_start = start_ip.replace("'", "''")
                    safe_end = end_ip.replace("'", "''")
                    conditions.append(f"multiIf({col_expr} = '', 0, isNull(IPv4StringToNumOrNull({col_expr})), 0, IPv4StringToNumOrNull({col_expr}) >= IPv4StringToNumOrNull('{safe_start}') AND IPv4StringToNumOrNull({col_expr}) <= IPv4StringToNumOrNull('{safe_end}'), 1, 0) = 1")
                elif cls._is_wildcard_ip(part):
                    # Handle wildcard IP
                    prefix = part.split('*')[0]
                    conditions.append(f"{col_expr} LIKE '{prefix}%'")
                else:
                    # Exact IP match
                    conditions.append(f"{col_expr} = '{safe_part}'")

            if conditions:
                combined = f"({' OR '.join(conditions)})"
                if negated:
                    return f"NOT {combined}"
                return combined

        # Handle severity as integer
        if field == 'severity':
            try:
                int_val = int(value)
                if negated:
                    return f"severity != {int_val}"
                return f"severity = {int_val}"
            except ValueError:
                pass

        # Handle port ranges (e.g., 80-443) - only for '=' operator
        if field in ('srcport', 'dstport', 'src_port', 'dst_port') and '-' in value and operator == '=':
            parts = value.split('-')
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start_port, end_port = parts
                port_expr = f"toUInt16OrNull({col_expr})"
                condition = f"{port_expr} IS NOT NULL AND {port_expr} >= {start_port} AND {port_expr} <= {end_port}"
                if negated:
                    return f"NOT ({condition})"
                return condition

        # Handle OR logic with pipe separator (e.g., action:accept|allow|close)
        if '|' in value and operator == '=':
            or_values = [v.strip().replace("'", "''") for v in value.split('|')]
            or_conditions = [f"lower({col_expr}) = lower('{v}')" for v in or_values]
            combined = f"({' OR '.join(or_conditions)})"
            if negated:
                return f"NOT {combined}"
            return combined

        # Handle contains/like operator (~)
        if operator == '~':
            # Convert wildcards to SQL LIKE pattern
            like_value = safe_value.replace('*', '%')
            if '%' not in like_value:
                # If no wildcards, wrap with % for contains
                like_value = f"%{like_value}%"
            if negated:
                return f"{col_expr} NOT ILIKE '{like_value}'"
            return f"{col_expr} ILIKE '{like_value}'"

        # Handle comparison operators for numeric fields
        if operator in ('>', '>=', '<', '<='):
            numeric_fields = ('srcport', 'dstport', 'src_port', 'dst_port', 'severity',
                            'sentbyte', 'rcvdbyte', 'duration', 'policyid')
            if field in numeric_fields:
                try:
                    num_val = int(value)
                    if field == 'severity':
                        return f"severity {operator} {num_val}"
                    else:
                        num_expr = f"toInt64OrNull({col_expr})"
                        return f"{num_expr} IS NOT NULL AND {num_expr} {operator} {num_val}"
                except ValueError:
                    pass
            # For non-numeric fields, fall back to string comparison
            return f"{col_expr} {operator} '{safe_value}'"

        # Standard string comparison (case-insensitive) for '=' operator
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
            # Format datetime for ClickHouse (replace T with space, remove microseconds)
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            where_clauses.append(f"timestamp >= '{start_str}'")

        if end_time:
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
            where_clauses.append(f"timestamp <= '{end_str}'")

        if query_text:
            terms = cls._parse_advanced_query(query_text)

            if terms:
                for term in terms:
                    if term['type'] == 'field':
                        condition = cls._build_field_condition(
                            term['field'],
                            term['value'],
                            term['negated'],
                            term.get('operator', '=')
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
        default_hours: int = 1
    ) -> List[Dict[str, Any]]:
        """Search logs with advanced filtering. Defaults to last 1 hour for performance."""
        client = cls.get_client()

        # Build time filter separately for PREWHERE optimization
        prewhere_parts = []

        if start_time is None and end_time is None:
            prewhere_parts.append(f"timestamp > now() - INTERVAL {default_hours} HOUR")
        else:
            if start_time:
                start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp >= '{start_str}'")
            if end_time:
                end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp <= '{end_str}'")

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)

        # Use PREWHERE for time filter (allows skipping data blocks early)
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        query = f"""
        SELECT timestamp, device_ip, facility, severity, message, raw,
               srcip, dstip, srcport, dstport, proto, action, parsed_data
        FROM syslogs
        PREWHERE {prewhere_clause}
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
        default_hours: int = 1,
        max_count: int = 100000
    ) -> int:
        """
        Count logs matching filters with performance optimizations.

        For large datasets, uses LIMIT to cap counting at max_count for speed.
        Returns -1 if count exceeds max_count (indicates "100,000+" logs).
        """
        client = cls.get_client()

        # Build time filter separately for PREWHERE optimization
        prewhere_parts = []

        if start_time is None and end_time is None:
            prewhere_parts.append(f"timestamp > now() - INTERVAL {default_hours} HOUR")
        else:
            if start_time:
                start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp >= '{start_str}'")
            if end_time:
                end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp <= '{end_str}'")

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)

        # Use PREWHERE for time filter
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        # Use LIMIT to cap counting for performance (avoids counting millions of rows)
        # We check if there are more than max_count results
        query = f"""
        SELECT count() as total
        FROM (
            SELECT 1
            FROM syslogs
            PREWHERE {prewhere_clause}
            WHERE {where_sql}
            LIMIT {max_count + 1}
        )
        """

        result = client.query(query).result_rows
        count = result[0][0] if result else 0

        # Return -1 to indicate "100,000+" logs
        if count > max_count:
            return -1
        return count

    @classmethod
    def get_log_stats_summary(
        cls,
        device_ips: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        default_hours: int = 1
    ) -> Dict[str, Any]:
        """Get summary statistics for logs matching the current filters."""
        client = cls.get_client()

        # Build time filter separately for PREWHERE optimization
        prewhere_parts = []

        if start_time is None and end_time is None:
            prewhere_parts.append(f"timestamp > now() - INTERVAL {default_hours} HOUR")
        else:
            if start_time:
                start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp >= '{start_str}'")
            if end_time:
                end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
                prewhere_parts.append(f"timestamp <= '{end_str}'")

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, None, None, None, query_text, None)

        # Use PREWHERE for time filter
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        query = f"""
        SELECT
            count() as total_logs,
            uniq(device_ip) as unique_devices,
            countIf(severity <= 3) as critical_count,
            countIf(severity = 4) as warning_count,
            countIf(severity >= 5) as info_count
        FROM syslogs
        PREWHERE {prewhere_clause}
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
    def get_per_device_storage(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get storage usage breakdown per device.

        Uses a time window (default 24 hours) for performance with large tables.
        Storage is estimated using overall compression ratio from system tables.
        """
        client = cls.get_client()

        # Get device counts and recent activity (fast with time filter)
        query = f"""
        SELECT
            toString(device_ip) as device_ip,
            count() as log_count,
            max(timestamp) as newest_log
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY device_ip
        ORDER BY log_count DESC
        """

        results = list(client.query(query).named_results())

        # Get overall storage stats to estimate per-device storage
        try:
            storage = cls.get_storage_stats()
            total_rows = storage.get('total_rows', 1) or 1
            total_bytes = storage.get('uncompressed_bytes', 0) or 0
            avg_bytes_per_row = total_bytes / total_rows if total_rows > 0 else 500
        except Exception:
            avg_bytes_per_row = 500  # Reasonable default

        # Estimate storage per device based on log count
        for r in results:
            count = r.get('log_count', 0) or 0
            r['total_raw_size'] = int(avg_bytes_per_row * count)
            r['oldest_log'] = None  # Not fetched for speed
            r['avg_raw_size'] = avg_bytes_per_row

        return results

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
    def get_field_values(cls, field: str, limit: int = 20, hours: int = 24) -> List[str]:
        """
        Get distinct values for a parsed_data field from recent logs.

        Used for search autocomplete suggestions.
        """
        client = cls.get_client()

        # Map field names to actual column expressions with fallback for vendor variations
        field_mapping = {
            'srcip': "if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip'])",
            'dstip': "if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip'])",
            'srcport': "if(parsed_data['srcport'] != '', parsed_data['srcport'], parsed_data['src_port'])",
            'dstport': "if(parsed_data['dstport'] != '', parsed_data['dstport'], parsed_data['dst_port'])",
            'action': "if(action != '', action, parsed_data['action'])",
            'proto': "if(parsed_data['proto'] != '', parsed_data['proto'], parsed_data['protocol'])",
            'app': "if(parsed_data['app'] != '', parsed_data['app'], parsed_data['application'])",
            'srcintf': "if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if'])",
            'dstintf': "if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if'])",
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
            'policyname': "if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule'])",
            'srccountry': "if(parsed_data['srccountry'] != '', parsed_data['srccountry'], parsed_data['src_location'])",
            'dstcountry': "if(parsed_data['dstcountry'] != '', parsed_data['dstcountry'], parsed_data['dst_location'])",
            'appcat': "if(parsed_data['appcat'] != '', parsed_data['appcat'], parsed_data['category_of_app'])",
            'srczone': "if(parsed_data['srczone'] != '', parsed_data['srczone'], parsed_data['src_zone'])",
            'dstzone': "if(parsed_data['dstzone'] != '', parsed_data['dstzone'], parsed_data['dst_zone'])",
            'srcuser': "if(parsed_data['srcuser'] != '', parsed_data['srcuser'], parsed_data['src_user'])",
            'dstuser': "if(parsed_data['dstuser'] != '', parsed_data['dstuser'], parsed_data['dst_user'])",
            'type': "parsed_data['type']",
            'subtype': "parsed_data['subtype']",
            'device': "toString(device_ip)",
            'device_name': "if(parsed_data['device_name'] != '', parsed_data['device_name'], parsed_data['devname'])",
            'rule': "if(parsed_data['rule'] != '', parsed_data['rule'], parsed_data['policyname'])",
            'session_end_reason': "parsed_data['session_end_reason']",
        }

        col_expr = field_mapping.get(field, f"parsed_data['{field}']")

        query = f"""
        SELECT DISTINCT {col_expr} as value
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
          AND {col_expr} != ''
        ORDER BY value
        LIMIT {limit}
        """

        try:
            result = client.query(query).result_rows
            return [row[0] for row in result if row[0]]
        except Exception as e:
            logger.warning(f"Failed to get field values for {field}: {e}")
            return []

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
            if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip']) as srcip,
            if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip']) as dstip,
            if(parsed_data['srcport'] != '', parsed_data['srcport'], parsed_data['src_port']) as srcport,
            if(parsed_data['dstport'] != '', parsed_data['dstport'], parsed_data['dst_port']) as dstport,
            if(parsed_data['proto'] != '', parsed_data['proto'], parsed_data['protocol']) as proto,
            if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if']) as srcintf,
            if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if']) as dstintf,
            parsed_data['policyid'] as policyid,
            if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule']) as policyname,
            parsed_data['service'] as service,
            if(parsed_data['duration'] != '', parsed_data['duration'], parsed_data['elapsed_time']) as duration,
            if(parsed_data['sentbyte'] != '', parsed_data['sentbyte'], parsed_data['bytes_sent']) as sentbyte,
            if(parsed_data['rcvdbyte'] != '', parsed_data['rcvdbyte'], parsed_data['bytes_recv']) as rcvdbyte,
            parsed_data['session_end_reason'] as session_end_reason
        FROM syslogs
        WHERE
            (parsed_data['srcip'] = '{safe_srcip}' OR parsed_data['src_ip'] = '{safe_srcip}')
            AND (parsed_data['dstip'] = '{safe_dstip}' OR parsed_data['dst_ip'] = '{safe_dstip}')
            AND (parsed_data['dstport'] = '{safe_dstport}' OR parsed_data['dst_port'] = '{safe_dstport}')
            AND (parsed_data['proto'] = '{safe_proto}' OR parsed_data['protocol'] = '{safe_proto}')
            AND timestamp BETWEEN
                toDateTime64('{ts_str}', 3) - INTERVAL {time_window_seconds} SECOND
                AND toDateTime64('{ts_str}', 3) + INTERVAL {time_window_seconds} SECOND
        ORDER BY timestamp ASC
        """

        result = list(client.query(query).named_results())
        return result

    # Dashboard cache for performance
    _dashboard_cache: Dict[str, Any] = {}
    _dashboard_cache_time: float = 0
    _DASHBOARD_CACHE_TTL: int = 30  # Cache for 30 seconds

    @classmethod
    def get_dashboard_stats(cls) -> Dict[str, Any]:
        """
        Get comprehensive dashboard statistics for SIEM dashboard.
        Uses caching and optimized queries for fast performance.
        """
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Check cache first
        now = time.time()
        if cls._dashboard_cache and (now - cls._dashboard_cache_time) < cls._DASHBOARD_CACHE_TTL:
            return cls._dashboard_cache

        # Define all queries - optimized for performance
        queries = {
            'totals': """
                SELECT
                    count() as total_24h,
                    count() / (24 * 3600) as avg_eps,
                    countIf(timestamp > now() - INTERVAL 1 HOUR) as total_1h,
                    countIf(timestamp > now() - INTERVAL 1 HOUR) / 3600 as current_eps
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
            """,
            'severity': """
                SELECT severity, count() as count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
                GROUP BY severity ORDER BY severity
            """,
            'actions': """
                SELECT lower(action) as action_type, count() as count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR AND action != ''
                GROUP BY action_type ORDER BY count DESC LIMIT 10
            """,
            'top_sources': """
                SELECT srcip as ip, count() as count, 0 as denied_count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR AND srcip != ''
                GROUP BY srcip ORDER BY count DESC LIMIT 10
            """,
            'top_destinations': """
                SELECT dstip as ip, count() as count, 0 as denied_count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR AND dstip != ''
                GROUP BY dstip ORDER BY count DESC LIMIT 10
            """,
            'threats': """
                SELECT srcip as ip, count() as denied_count, uniq(dstip) as unique_targets, uniq(dstport) as unique_ports
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
                  AND lower(action) IN ('deny', 'drop', 'block', 'reject') AND srcip != ''
                GROUP BY srcip ORDER BY denied_count DESC LIMIT 10
            """,
            'ports': """
                SELECT dstport as port, count() as count, 0 as denied_count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR AND dstport > 0
                GROUP BY dstport ORDER BY count DESC LIMIT 10
            """,
            'devices': """
                SELECT toString(device_ip) as device, count() as log_count, max(timestamp) as last_seen,
                    countIf(severity <= 3) as critical_count, 0 as denied_count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
                GROUP BY device_ip ORDER BY log_count DESC
            """,
            'timeline': """
                SELECT toStartOfHour(timestamp) as hour, count() as total,
                    countIf(severity <= 3) as critical,
                    countIf(lower(action) IN ('deny', 'drop', 'block', 'reject')) as denied
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
                GROUP BY hour ORDER BY hour
            """,
            'realtime': """
                SELECT toStartOfMinute(timestamp) as minute, count() as count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 1 HOUR
                GROUP BY minute ORDER BY minute
            """,
            'protocol': """
                SELECT multiIf(proto = 6, 'TCP', proto = 17, 'UDP', proto = 1, 'ICMP', proto = 0, 'Unknown', toString(proto)) as protocol,
                    count() as count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR AND proto > 0
                GROUP BY proto ORDER BY count DESC LIMIT 5
            """,
        }

        def run_query(name: str, query: str) -> tuple:
            """Execute a single query and return results."""
            try:
                client = cls.get_client()
                result = list(client.query(query).named_results())
                return (name, result)
            except Exception as e:
                logger.error(f"Dashboard query '{name}' failed: {e}")
                return (name, [])

        # Execute all queries in parallel using ThreadPoolExecutor
        results = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(run_query, name, query): name for name, query in queries.items()}
            for future in as_completed(futures):
                name, result = future.result()
                results[name] = result

        # Build stats dictionary from results
        stats = {}

        # Process totals
        if results.get('totals'):
            r = results['totals'][0]
            stats['total_logs_24h'] = r.get('total_24h', 0)
            stats['avg_eps'] = round(r.get('avg_eps', 0), 1)
            stats['total_logs_1h'] = r.get('total_1h', 0)
            stats['current_eps'] = round(r.get('current_eps', 0), 1)

        # Process severity
        severity_result = results.get('severity', [])
        stats['severity_breakdown'] = severity_result
        stats['critical_count'] = sum(r['count'] for r in severity_result if r['severity'] <= 3)
        stats['warning_count'] = sum(r['count'] for r in severity_result if r['severity'] == 4)
        stats['info_count'] = sum(r['count'] for r in severity_result if r['severity'] >= 5)

        # Process actions
        action_result = results.get('actions', [])
        stats['action_breakdown'] = action_result
        allow_actions = ['accept', 'allow', 'pass', 'close', 'client-rst', 'server-rst']
        deny_actions = ['deny', 'drop', 'block', 'reject']
        stats['allowed_count'] = sum(r['count'] for r in action_result if r.get('action_type') in allow_actions)
        stats['denied_count'] = sum(r['count'] for r in action_result if r.get('action_type') in deny_actions)

        # Direct assignments
        stats['top_sources'] = results.get('top_sources', [])
        stats['top_destinations'] = results.get('top_destinations', [])
        stats['potential_threats'] = results.get('threats', [])
        stats['top_ports'] = results.get('ports', [])
        stats['device_activity'] = results.get('devices', [])
        stats['active_devices'] = len(stats['device_activity'])
        stats['traffic_timeline'] = results.get('timeline', [])
        stats['realtime_traffic'] = results.get('realtime', [])
        stats['protocol_distribution'] = results.get('protocol', [])

        # Skip geo query for now - it's too slow (access parsed_data Map)
        # Can be added back with a dedicated materialized column later
        stats['geo_sources'] = []

        # Update cache
        cls._dashboard_cache = stats
        cls._dashboard_cache_time = now

        return stats

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

        # First get the original log - use a small window for timestamp matching
        safe_device = device_ip.replace("'", "''")

        # Clean up timestamp format - handle various formats
        clean_timestamp = log_timestamp.replace('T', ' ').replace('Z', '')
        # Remove microseconds if present beyond 3 digits
        if '.' in clean_timestamp:
            parts = clean_timestamp.split('.')
            if len(parts[1]) > 3:
                clean_timestamp = parts[0] + '.' + parts[1][:3]

        # Use a 1-second window to find the log (handles precision issues)
        query = f"""
        SELECT
            timestamp,
            toString(device_ip) as device_ip,
            severity,
            parsed_data
        FROM syslogs
        WHERE
            toString(device_ip) = '{safe_device}'
            AND timestamp >= toDateTime64('{clean_timestamp}', 3) - INTERVAL 1 SECOND
            AND timestamp <= toDateTime64('{clean_timestamp}', 3) + INTERVAL 1 SECOND
        ORDER BY timestamp ASC
        LIMIT 1
        """

        original = list(client.query(query).named_results())
        if not original:
            return {'original_log': None, 'flow': [], 'summary': {}}

        original_log = original[0]
        pd = original_log.get('parsed_data', {})

        # Get fields with fallback for both Fortinet and Palo Alto field names
        srcip = pd.get('srcip') or pd.get('src_ip', '')
        dstip = pd.get('dstip') or pd.get('dst_ip', '')
        dstport = pd.get('dstport') or pd.get('dst_port', '')
        proto = pd.get('proto') or pd.get('protocol', '')

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
