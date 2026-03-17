"""
High-performance ClickHouse client for log ingestion and querying.
Migrated from Django to FastAPI with async support.
"""

import re
import logging
import threading
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
    - Thread-local connection reuse (one client per thread, no leaks)
    - Optimized table schema with partitioning
    - Batch insert support
    - Compression settings for storage efficiency
    """

    _local = threading.local()
    _all_clients: list = []      # track for shutdown cleanup
    _all_clients_lock = threading.Lock()

    @classmethod
    def _create_client(cls) -> Client:
        """Create a new clickhouse_connect client."""
        client = clickhouse_connect.get_client(
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
        with cls._all_clients_lock:
            cls._all_clients.append(client)
        return client

    @classmethod
    def get_client(cls) -> Client:
        """Return a thread-local reusable client.

        Each thread gets its own client (avoids "concurrent queries
        within the same session" errors).  Clients are reused within
        the same thread to prevent connection leaks that previously
        exhausted the ephemeral port range ([Errno 99]).
        """
        client = getattr(cls._local, 'client', None)
        if client is not None:
            try:
                client.ping()
                return client
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
                cls._local.client = None

        try:
            cls._local.client = cls._create_client()
            return cls._local.client
        except Exception as e:
            logger.error(f"Failed to connect to ClickHouse: {e}")
            raise

    @classmethod
    def close_client(cls) -> None:
        """Close all tracked clients (call during shutdown)."""
        with cls._all_clients_lock:
            for client in cls._all_clients:
                try:
                    client.close()
                except Exception:
                    pass
            cls._all_clients.clear()
        cls._local = threading.local()

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
            policyname LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),

            -- Additional indexed columns for Palo Alto and advanced queries
            log_type LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
            application LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
            src_zone LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
            dst_zone LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
            session_end_reason LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
            threat_id String DEFAULT '' CODEC(ZSTD(1)),
            vdom LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),

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
            INDEX idx_policyname policyname TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_message message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
            -- Indexes for Palo Alto specific queries
            INDEX idx_log_type log_type TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_application application TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_src_zone src_zone TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dst_zone dst_zone TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_session_end_reason session_end_reason TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_threat_id threat_id TYPE bloom_filter(0.01) GRANULARITY 4
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
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS policyname String DEFAULT '' CODEC(ZSTD(1))",
            # Add Palo Alto specific indexed columns
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_type String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS application String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS src_zone String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS dst_zone String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS session_end_reason String DEFAULT '' CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS threat_id String DEFAULT '' CODEC(ZSTD(1))",
            # Keep parsed_data for other fields
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS parsed_data Map(String, String) CODEC(ZSTD(1))",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_date Date MATERIALIZED toDate(timestamp)",
            "ALTER TABLE syslogs ADD COLUMN IF NOT EXISTS log_hour UInt8 MATERIALIZED toHour(timestamp)",
            # Add indexes for original columns
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_srcip srcip TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_dstip dstip TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_srcport srcport TYPE minmax GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_dstport dstport TYPE minmax GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_action action TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_policyname policyname TYPE bloom_filter(0.01) GRANULARITY 4",
            # Add indexes for Palo Alto specific columns
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_log_type log_type TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_application application TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_src_zone src_zone TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_dst_zone dst_zone TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_session_end_reason session_end_reason TYPE bloom_filter(0.01) GRANULARITY 4",
            "ALTER TABLE syslogs ADD INDEX IF NOT EXISTS idx_threat_id threat_id TYPE bloom_filter(0.01) GRANULARITY 4",
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
    def backfill_new_indexed_columns(cls) -> Dict[str, Any]:
        """
        Backfill new indexed columns from parsed_data for existing records.

        This populates: srcip, dstip, log_type, application, src_zone, dst_zone,
        session_end_reason, threat_id for records inserted before these columns were added.

        Returns status dict with mutation info.
        """
        client = cls.get_client()

        # Check how many rows need updating (sample check on srcip)
        check_query = """
        SELECT count() as needs_update
        FROM syslogs
        WHERE srcip = '' AND (parsed_data['srcip'] != '' OR parsed_data['src_ip'] != '')
        """
        result = client.query(check_query).result_rows
        empty_count = result[0][0] if result else 0

        if empty_count == 0:
            return {'status': 'complete', 'rows_updated': 0, 'message': 'No rows need backfilling'}

        # Backfill all new indexed columns
        mutations = [
            # IP columns
            """ALTER TABLE syslogs UPDATE srcip = if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip'])
               WHERE srcip = '' AND (parsed_data['srcip'] != '' OR parsed_data['src_ip'] != '')""",
            """ALTER TABLE syslogs UPDATE dstip = if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip'])
               WHERE dstip = '' AND (parsed_data['dstip'] != '' OR parsed_data['dst_ip'] != '')""",
            # Log type (Fortinet: type/subtype, Palo Alto: log_type)
            """ALTER TABLE syslogs UPDATE log_type = if(parsed_data['log_type'] != '', parsed_data['log_type'],
                   if(parsed_data['type'] != '', concat(parsed_data['type'], if(parsed_data['subtype'] != '', concat('/', parsed_data['subtype']), '')), ''))
               WHERE log_type = '' AND (parsed_data['log_type'] != '' OR parsed_data['type'] != '')""",
            # Application (Fortinet: app, Palo Alto: application)
            """ALTER TABLE syslogs UPDATE application = if(parsed_data['app'] != '', parsed_data['app'], parsed_data['application'])
               WHERE application = '' AND (parsed_data['app'] != '' OR parsed_data['application'] != '')""",
            # Source zone (Fortinet: srcintf, Palo Alto: src_zone)
            """ALTER TABLE syslogs UPDATE src_zone = multiIf(
                   parsed_data['src_zone'] != '', parsed_data['src_zone'],
                   parsed_data['srczone'] != '', parsed_data['srczone'],
                   parsed_data['srcintf'] != '', parsed_data['srcintf'], '')
               WHERE src_zone = '' AND (parsed_data['src_zone'] != '' OR parsed_data['srczone'] != '' OR parsed_data['srcintf'] != '')""",
            # Destination zone (Fortinet: dstintf, Palo Alto: dst_zone)
            """ALTER TABLE syslogs UPDATE dst_zone = multiIf(
                   parsed_data['dst_zone'] != '', parsed_data['dst_zone'],
                   parsed_data['dstzone'] != '', parsed_data['dstzone'],
                   parsed_data['dstintf'] != '', parsed_data['dstintf'], '')
               WHERE dst_zone = '' AND (parsed_data['dst_zone'] != '' OR parsed_data['dstzone'] != '' OR parsed_data['dstintf'] != '')""",
            # Session end reason (Palo Alto specific)
            """ALTER TABLE syslogs UPDATE session_end_reason = parsed_data['session_end_reason']
               WHERE session_end_reason = '' AND parsed_data['session_end_reason'] != ''""",
            # Threat ID (Palo Alto specific)
            """ALTER TABLE syslogs UPDATE threat_id = parsed_data['threat_id']
               WHERE threat_id = '' AND parsed_data['threat_id'] != ''""",
        ]

        try:
            logger.info(f"Starting backfill for approximately {empty_count:,} rows...")
            for mutation in mutations:
                try:
                    client.command(mutation)
                except Exception as e:
                    logger.warning(f"Mutation skipped (may not apply): {e}")

            logger.info("Backfill mutations scheduled. Run 'SELECT * FROM system.mutations WHERE is_done = 0' to check status.")
            return {
                'status': 'scheduled',
                'rows_to_update': empty_count,
                'mutations_scheduled': len(mutations),
                'message': 'Backfill mutations scheduled. ClickHouse will process them asynchronously.'
            }
        except Exception as e:
            logger.error(f"Backfill failed: {e}")
            return {'status': 'error', 'message': str(e)}

    @classmethod
    def backfill_policyname_column(cls) -> Dict[str, Any]:
        """
        Backfill policyname column from parsed_data for existing records.

        This is a one-time migration to populate the indexed policyname column
        for records that were inserted before the optimization.

        Supports both Fortinet (policyname) and Palo Alto (rule) field names.

        Returns status dict with rows_updated count.
        """
        client = cls.get_client()

        # Check how many rows need updating
        check_query = """
        SELECT count() as empty_policyname
        FROM syslogs
        WHERE policyname = '' AND (parsed_data['policyname'] != '' OR parsed_data['rule'] != '')
        """
        result = client.query(check_query).result_rows
        empty_count = result[0][0] if result else 0

        if empty_count == 0:
            return {'status': 'complete', 'rows_updated': 0, 'message': 'No rows need backfilling'}

        # Backfill policyname column (Fortinet: policyname, Palo Alto: rule)
        policyname_query = """
        ALTER TABLE syslogs
        UPDATE policyname = if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule'])
        WHERE policyname = '' AND (parsed_data['policyname'] != '' OR parsed_data['rule'] != '')
        """

        try:
            logger.info(f"Starting policyname backfill for approximately {empty_count:,} rows...")
            client.command(policyname_query)
            logger.info("Policyname backfill mutation scheduled. Run 'SELECT * FROM system.mutations WHERE is_done = 0' to check status.")
            return {
                'status': 'scheduled',
                'rows_to_update': empty_count,
                'message': 'Policyname backfill mutation scheduled. ClickHouse will process it asynchronously.'
            }
        except Exception as e:
            logger.error(f"Policyname backfill failed: {e}")
            return {'status': 'error', 'message': str(e)}

    # ── Palo Alto Threat/URL Dedicated Table ────────────────────────────
    # Column order for insert_threat_logs() — must match CREATE TABLE order
    PA_THREAT_COLUMNS = [
        'timestamp', 'receive_time', 'generated_time',
        'serial_number', 'device_name', 'vsys', 'vsys_name', 'device_ip',
        'log_subtype', 'severity', 'direction', 'action',
        'src_ip', 'dest_ip', 'src_port', 'dest_port', 'transport',
        'src_translated_ip', 'dest_translated_ip', 'src_translated_port', 'dest_translated_port',
        'src_zone', 'dest_zone', 'src_interface', 'dest_interface',
        'src_user', 'dest_user', 'application',
        'rule', 'rule_uuid', 'log_forwarding_profile',
        'threat_id', 'threat_name', 'threat_numeric_id', 'threat_category', 'category',
        'url', 'content_type', 'user_agent', 'http_method', 'xff', 'xff_ip',
        'referrer', 'reason', 'justification',
        'file_name', 'file_hash', 'file_type', 'cloud_address', 'report_id',
        'sender', 'subject', 'recipient',
        'session_id', 'repeat_count', 'pcap_id',
        'src_location', 'dest_location',
        'sequence_number', 'action_flags', 'content_version',
        'tunnel_id', 'tunnel_type',
        'src_edl', 'dest_edl',
        'dynusergroup_name', 'src_dag', 'dest_dag',
        'subcategory_of_app', 'category_of_app', 'technology_of_app',
        'risk_of_app', 'is_saas', 'sanctioned_state',
        'src_dvc_category', 'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os',
        'src_hostname', 'src_mac',
        'dest_dvc_category', 'dest_dvc_model', 'dest_dvc_vendor', 'dest_dvc_os',
        'dest_hostname', 'dest_mac',
        'url_category_list',
        'http2_connection',
    ]

    @classmethod
    def ensure_pa_threat_table(cls) -> None:
        """Create the dedicated pa_threat_logs table for Palo Alto threat/URL logs."""
        client = cls.get_client()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS pa_threat_logs (
            -- Timestamps
            timestamp           DateTime64(3) CODEC(DoubleDelta, LZ4),
            receive_time        DateTime64(3) CODEC(DoubleDelta, LZ4),
            generated_time      DateTime64(3) CODEC(DoubleDelta, LZ4),

            -- Device Identity
            serial_number       String CODEC(ZSTD(1)),
            device_name         LowCardinality(String),
            vsys                LowCardinality(String),
            vsys_name           LowCardinality(String),
            device_ip           String CODEC(ZSTD(1)),

            -- Log Classification
            log_subtype         LowCardinality(String),
            severity            LowCardinality(String),
            direction           LowCardinality(String),
            action              LowCardinality(String),

            -- Network 5-Tuple
            src_ip              String CODEC(ZSTD(1)),
            dest_ip             String CODEC(ZSTD(1)),
            src_port            UInt16 CODEC(T64, LZ4),
            dest_port           UInt16 CODEC(T64, LZ4),
            transport           LowCardinality(String),

            -- NAT
            src_translated_ip   String DEFAULT '' CODEC(ZSTD(1)),
            dest_translated_ip  String DEFAULT '' CODEC(ZSTD(1)),
            src_translated_port UInt16 DEFAULT 0 CODEC(T64, LZ4),
            dest_translated_port UInt16 DEFAULT 0 CODEC(T64, LZ4),

            -- Zones & Interfaces
            src_zone            LowCardinality(String),
            dest_zone           LowCardinality(String),
            src_interface       LowCardinality(String),
            dest_interface      LowCardinality(String),

            -- Identity
            src_user            String DEFAULT '' CODEC(ZSTD(1)),
            dest_user           String DEFAULT '' CODEC(ZSTD(1)),
            application         LowCardinality(String),

            -- Policy
            rule                LowCardinality(String),
            rule_uuid           String DEFAULT '' CODEC(ZSTD(1)),
            log_forwarding_profile LowCardinality(String),

            -- Threat Details
            threat_id           String CODEC(ZSTD(1)),
            threat_name         String CODEC(ZSTD(1)),
            threat_numeric_id   UInt64 DEFAULT 0 CODEC(T64, LZ4),
            threat_category     LowCardinality(String),
            category            LowCardinality(String),

            -- URL Filtering Fields (populated when log_subtype = 'url')
            url                 String DEFAULT '' CODEC(ZSTD(3)),
            content_type        LowCardinality(String),
            user_agent          String DEFAULT '' CODEC(ZSTD(3)),
            http_method         LowCardinality(String),
            xff                 String DEFAULT '' CODEC(ZSTD(1)),
            xff_ip              String DEFAULT '' CODEC(ZSTD(1)),
            referrer            String DEFAULT '' CODEC(ZSTD(3)),
            reason              String DEFAULT '' CODEC(ZSTD(1)),
            justification       String DEFAULT '' CODEC(ZSTD(1)),

            -- File & WildFire Fields
            file_name           String DEFAULT '' CODEC(ZSTD(1)),
            file_hash           String DEFAULT '' CODEC(ZSTD(1)),
            file_type           LowCardinality(String),
            cloud_address       String DEFAULT '' CODEC(ZSTD(1)),
            report_id           String DEFAULT '' CODEC(ZSTD(1)),

            -- Email Fields (WildFire)
            sender              String DEFAULT '' CODEC(ZSTD(1)),
            subject             String DEFAULT '' CODEC(ZSTD(1)),
            recipient           String DEFAULT '' CODEC(ZSTD(1)),

            -- Session
            session_id          UInt64 DEFAULT 0 CODEC(T64, LZ4),
            repeat_count        UInt16 DEFAULT 0 CODEC(T64, LZ4),
            pcap_id             String DEFAULT '' CODEC(ZSTD(1)),

            -- Geo Location
            src_location        LowCardinality(String),
            dest_location       LowCardinality(String),

            -- Sequence & Versioning
            sequence_number     UInt64 DEFAULT 0 CODEC(T64, LZ4),
            action_flags        String DEFAULT '' CODEC(ZSTD(1)),
            content_version     String DEFAULT '' CODEC(ZSTD(1)),

            -- Tunnel
            tunnel_id           String DEFAULT '' CODEC(ZSTD(1)),
            tunnel_type         LowCardinality(String),

            -- EDL (PAN-OS 10.0+)
            src_edl             String DEFAULT '' CODEC(ZSTD(1)),
            dest_edl            String DEFAULT '' CODEC(ZSTD(1)),

            -- Dynamic Groups (PAN-OS 10.0+)
            dynusergroup_name   String DEFAULT '' CODEC(ZSTD(1)),
            src_dag             String DEFAULT '' CODEC(ZSTD(1)),
            dest_dag            String DEFAULT '' CODEC(ZSTD(1)),

            -- App Metadata (PAN-OS 10.2+)
            subcategory_of_app  LowCardinality(String),
            category_of_app     LowCardinality(String),
            technology_of_app   LowCardinality(String),
            risk_of_app         UInt8 DEFAULT 0,
            is_saas             UInt8 DEFAULT 0,
            sanctioned_state    UInt8 DEFAULT 0,

            -- Device-ID (PAN-OS 10.2+)
            src_dvc_category    LowCardinality(String),
            src_dvc_model       String DEFAULT '' CODEC(ZSTD(1)),
            src_dvc_vendor      LowCardinality(String),
            src_dvc_os          LowCardinality(String),
            src_hostname        String DEFAULT '' CODEC(ZSTD(1)),
            src_mac             String DEFAULT '' CODEC(ZSTD(1)),
            dest_dvc_category   LowCardinality(String),
            dest_dvc_model      String DEFAULT '' CODEC(ZSTD(1)),
            dest_dvc_vendor     LowCardinality(String),
            dest_dvc_os         LowCardinality(String),
            dest_hostname       String DEFAULT '' CODEC(ZSTD(1)),
            dest_mac            String DEFAULT '' CODEC(ZSTD(1)),

            -- URL Category List (PAN-OS 10.0+, up to 4 categories)
            url_category_list   String DEFAULT '' CODEC(ZSTD(1)),

            -- HTTP/2
            http2_connection    UInt32 DEFAULT 0,

            -- Materialized for performance
            log_date            Date MATERIALIZED toDate(timestamp),
            log_hour            UInt8 MATERIALIZED toHour(timestamp),

            -- Indexes
            INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_threat_name threat_name TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_url url TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
            INDEX idx_category category TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_rule rule TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_severity severity TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_subtype log_subtype TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_src_user src_user TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_application application TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_file_hash file_hash TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_src_zone src_zone TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dest_zone dest_zone TYPE bloom_filter(0.01) GRANULARITY 4
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (log_subtype, severity, timestamp)
        TTL timestamp + INTERVAL 6 MONTH DELETE
        SETTINGS
            index_granularity = 8192,
            min_bytes_for_wide_part = 10485760,
            merge_with_ttl_timeout = 86400
        """

        try:
            client.command(create_table_query)
            logger.info("ClickHouse table 'pa_threat_logs' created/verified")
        except Exception as e:
            logger.warning(f"pa_threat_logs table creation issue: {e}")

        # Create materialized view for hourly aggregates
        hourly_mv_query = """
        CREATE MATERIALIZED VIEW IF NOT EXISTS pa_threat_hourly_mv
        ENGINE = SummingMergeTree()
        PARTITION BY toYYYYMM(hour)
        ORDER BY (hour, log_subtype, severity, action, category)
        TTL hour + INTERVAL 12 MONTH DELETE
        AS SELECT
            toStartOfHour(timestamp) AS hour,
            log_subtype,
            severity,
            action,
            category,
            count() AS event_count,
            uniqExact(src_ip) AS unique_sources,
            uniqExact(dest_ip) AS unique_destinations,
            uniqExact(threat_name) AS unique_threats
        FROM pa_threat_logs
        GROUP BY hour, log_subtype, severity, action, category
        """
        try:
            client.command(hourly_mv_query)
            logger.info("Materialized view 'pa_threat_hourly_mv' created/verified")
        except Exception as e:
            logger.debug(f"pa_threat_hourly_mv view: {e}")

        # Create materialized view for top threat sources
        top_sources_mv_query = """
        CREATE MATERIALIZED VIEW IF NOT EXISTS pa_threat_top_sources_mv
        ENGINE = SummingMergeTree()
        PARTITION BY toYYYYMM(day)
        ORDER BY (day, src_ip, log_subtype)
        TTL day + INTERVAL 3 MONTH DELETE
        AS SELECT
            toDate(timestamp) AS day,
            src_ip,
            log_subtype,
            count() AS event_count,
            uniqExact(threat_name) AS unique_threats,
            uniqExact(dest_ip) AS targets_count
        FROM pa_threat_logs
        GROUP BY day, src_ip, log_subtype
        """
        try:
            client.command(top_sources_mv_query)
            logger.info("Materialized view 'pa_threat_top_sources_mv' created/verified")
        except Exception as e:
            logger.debug(f"pa_threat_top_sources_mv view: {e}")

    # ── Unified URL / WebFilter Logs Table ──────────────────────────────
    URL_LOG_COLUMNS = [
        'timestamp', 'vendor', 'device_ip', 'device_name', 'vdom',
        'action', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'transport',
        'src_user', 'url', 'hostname', 'url_category', 'url_category_id',
        'http_method', 'user_agent', 'content_type', 'referrer', 'direction',
        'severity', 'policy', 'policy_id', 'application', 'service',
        'src_zone', 'dest_zone', 'src_country', 'dest_country',
        'sent_bytes', 'recv_bytes', 'session_id', 'msg', 'profile',
        'event_type', 'request_type',
    ]

    @classmethod
    def ensure_url_logs_table(cls) -> None:
        """Create the unified url_logs table for Fortinet WebFilter + Palo Alto URL logs."""
        client = cls.get_client()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS url_logs (
            -- Timestamps
            timestamp           DateTime64(3) CODEC(DoubleDelta, LZ4),

            -- Source identification
            vendor              LowCardinality(String),   -- 'fortinet' or 'paloalto'
            device_ip           String CODEC(ZSTD(1)),
            device_name         LowCardinality(String),
            vdom                LowCardinality(String),

            -- Action
            action              LowCardinality(String),

            -- Network 5-tuple
            src_ip              String CODEC(ZSTD(1)),
            dest_ip             String CODEC(ZSTD(1)),
            src_port            UInt16 CODEC(T64, LZ4),
            dest_port           UInt16 CODEC(T64, LZ4),
            transport           LowCardinality(String),

            -- Identity
            src_user            String DEFAULT '' CODEC(ZSTD(1)),

            -- URL / Web fields
            url                 String DEFAULT '' CODEC(ZSTD(3)),
            hostname            String DEFAULT '' CODEC(ZSTD(1)),
            url_category        LowCardinality(String),
            url_category_id     String DEFAULT '' CODEC(ZSTD(1)),
            http_method         LowCardinality(String),
            user_agent          String DEFAULT '' CODEC(ZSTD(3)),
            content_type        LowCardinality(String),
            referrer            String DEFAULT '' CODEC(ZSTD(3)),
            direction           LowCardinality(String),

            -- Severity / Classification
            severity            LowCardinality(String),

            -- Policy
            policy              LowCardinality(String),
            policy_id           String DEFAULT '' CODEC(ZSTD(1)),
            application         LowCardinality(String),
            service             LowCardinality(String),

            -- Zones
            src_zone            LowCardinality(String),
            dest_zone           LowCardinality(String),

            -- Geo
            src_country         LowCardinality(String),
            dest_country        LowCardinality(String),

            -- Bytes
            sent_bytes          UInt64 DEFAULT 0 CODEC(T64, LZ4),
            recv_bytes          UInt64 DEFAULT 0 CODEC(T64, LZ4),

            -- Session
            session_id          UInt64 DEFAULT 0 CODEC(T64, LZ4),

            -- Message / context
            msg                 String DEFAULT '' CODEC(ZSTD(1)),
            profile             LowCardinality(String),

            -- Fortinet-specific
            event_type          LowCardinality(String),  -- ftgd_allow, ftgd_blk, etc.
            request_type        LowCardinality(String),  -- direct, referral, etc.

            -- Materialized
            log_date            Date MATERIALIZED toDate(timestamp),
            log_hour            UInt8 MATERIALIZED toHour(timestamp),

            -- Indexes
            INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_url url TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
            INDEX idx_hostname hostname TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_url_category url_category TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_src_user src_user TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_policy policy TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_application application TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_vendor vendor TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_http_method http_method TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_severity severity TYPE bloom_filter(0.01) GRANULARITY 4
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (action, url_category, timestamp)
        TTL timestamp + INTERVAL 6 MONTH DELETE
        SETTINGS
            index_granularity = 8192,
            min_bytes_for_wide_part = 10485760,
            merge_with_ttl_timeout = 86400
        """

        try:
            client.command(create_table_query)
            logger.info("ClickHouse table 'url_logs' created/verified")
        except Exception as e:
            logger.warning(f"url_logs table creation issue: {e}")

    @classmethod
    def insert_url_logs(cls, logs: List[tuple]) -> None:
        """Insert URL/WebFilter logs into the unified url_logs table."""
        if not logs:
            return
        client = cls.get_client()
        client.insert('url_logs', logs, column_names=cls.URL_LOG_COLUMNS)

    # ── Unified DNS Logs Table ─────────────────────────────────────────
    DNS_LOG_COLUMNS = [
        'timestamp', 'vendor', 'device_ip', 'device_name', 'vdom',
        'action', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'transport',
        'src_user', 'qname', 'qtype', 'qclass', 'resolved_ip',
        'category', 'category_id', 'severity', 'direction',
        'policy', 'policy_id', 'profile',
        'src_zone', 'dest_zone', 'src_country', 'dest_country',
        'session_id', 'msg', 'event_type',
        'threat_name', 'threat_id',
    ]

    @classmethod
    def ensure_dns_logs_table(cls) -> None:
        """Create the unified dns_logs table for Fortinet DNS + Palo Alto DNS logs."""
        client = cls.get_client()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS dns_logs (
            -- Timestamps
            timestamp           DateTime64(3) CODEC(DoubleDelta, LZ4),

            -- Source identification
            vendor              LowCardinality(String),
            device_ip           String CODEC(ZSTD(1)),
            device_name         LowCardinality(String),
            vdom                LowCardinality(String),

            -- Action
            action              LowCardinality(String),

            -- Network 5-tuple
            src_ip              String CODEC(ZSTD(1)),
            dest_ip             String CODEC(ZSTD(1)),
            src_port            UInt16 CODEC(T64, LZ4),
            dest_port           UInt16 CODEC(T64, LZ4),
            transport           LowCardinality(String),

            -- Identity
            src_user            String DEFAULT '' CODEC(ZSTD(1)),

            -- DNS fields
            qname               String DEFAULT '' CODEC(ZSTD(1)),
            qtype               LowCardinality(String),
            qclass              LowCardinality(String),
            resolved_ip         String DEFAULT '' CODEC(ZSTD(1)),

            -- Classification
            category            LowCardinality(String),
            category_id         String DEFAULT '' CODEC(ZSTD(1)),
            severity            LowCardinality(String),
            direction           LowCardinality(String),

            -- Policy
            policy              LowCardinality(String),
            policy_id           String DEFAULT '' CODEC(ZSTD(1)),
            profile             LowCardinality(String),

            -- Zones
            src_zone            LowCardinality(String),
            dest_zone           LowCardinality(String),

            -- Geo
            src_country         LowCardinality(String),
            dest_country        LowCardinality(String),

            -- Session
            session_id          UInt64 DEFAULT 0 CODEC(T64, LZ4),

            -- Message / context
            msg                 String DEFAULT '' CODEC(ZSTD(1)),
            event_type          LowCardinality(String),

            -- Threat
            threat_name         String DEFAULT '' CODEC(ZSTD(1)),
            threat_id           String DEFAULT '' CODEC(ZSTD(1)),

            -- Materialized
            log_date            Date MATERIALIZED toDate(timestamp),
            log_hour            UInt8 MATERIALIZED toHour(timestamp),

            -- Indexes
            INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_qname qname TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
            INDEX idx_category category TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_src_user src_user TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_resolved_ip resolved_ip TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_threat_name threat_name TYPE bloom_filter(0.01) GRANULARITY 4,
            INDEX idx_vendor vendor TYPE bloom_filter(0.01) GRANULARITY 4
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (action, qname, timestamp)
        TTL timestamp + INTERVAL 6 MONTH DELETE
        SETTINGS
            index_granularity = 8192,
            min_bytes_for_wide_part = 10485760,
            merge_with_ttl_timeout = 86400
        """

        try:
            client.command(create_table_query)
            logger.info("ClickHouse table 'dns_logs' created/verified")
        except Exception as e:
            logger.warning(f"dns_logs table creation issue: {e}")

    @classmethod
    def insert_dns_logs(cls, logs: List[tuple]) -> None:
        """Insert DNS logs into the unified dns_logs table."""
        if not logs:
            return
        client = cls.get_client()
        client.insert('dns_logs', logs, column_names=cls.DNS_LOG_COLUMNS)

    @classmethod
    def insert_threat_logs(cls, logs: List[tuple]) -> None:
        """Insert Palo Alto threat/URL logs into the dedicated pa_threat_logs table."""
        if not logs:
            return
        client = cls.get_client()
        client.insert('pa_threat_logs', logs, column_names=cls.PA_THREAT_COLUMNS)

    @classmethod
    def insert_logs(cls, logs: List[Tuple]) -> None:
        """
        Insert logs in batch.

        Args:
            logs: List of tuples matching the schema columns
                  (timestamp, device_ip, facility, severity, message, raw,
                   srcip, dstip, srcport, dstport, proto, action, policyname,
                   log_type, application, src_zone, dst_zone, session_end_reason,
                   threat_id, vdom, parsed_data)
        """
        if not logs:
            return
        client = cls.get_client()

        client.insert('syslogs', logs, column_names=[
            'timestamp', 'device_ip', 'facility', 'severity', 'message', 'raw',
            'srcip', 'dstip', 'srcport', 'dstport', 'proto', 'action', 'policyname',
            'log_type', 'application', 'src_zone', 'dst_zone', 'session_end_reason',
            'threat_id', 'vdom', 'parsed_data'
        ])

    @classmethod
    def get_recent_logs(cls, limit: int = 100, include_raw: bool = False) -> List[Dict[str, Any]]:
        """
        Get most recent logs.

        Args:
            limit: Maximum number of logs to return
            include_raw: If False (default), excludes 'raw' and 'parsed_data' for performance
        """
        client = cls.get_client()
        columns = cls.FULL_COLUMNS if include_raw else cls.LIGHT_COLUMNS
        # Use PREWHERE on timestamp to limit scan range — without this,
        # ClickHouse scans the entire table which takes 45+ seconds on large datasets.
        # Try 1h first; if not enough rows, expand progressively.
        for hours in (1, 24):
            query = f"""
            SELECT {columns}
            FROM syslogs
            PREWHERE timestamp > now() - INTERVAL {hours} HOUR
            ORDER BY timestamp DESC
            LIMIT {limit}
            """
            result = list(client.query(query).named_results())
            if len(result) >= limit or hours == 24:
                return result
        return result

    @classmethod
    def get_log_by_id(
        cls,
        timestamp: str,
        device_ip: str,
        include_raw: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Get a single log entry by timestamp and device IP.

        Used for fetching full log details including raw message on demand.

        Args:
            timestamp: ISO format timestamp of the log
            device_ip: Device IP that logged the entry
            include_raw: If True (default), includes raw and parsed_data

        Returns:
            Log entry dict or None if not found
        """
        client = cls.get_client()
        device_where = cls._device_where(device_ip)

        # Clean up timestamp format
        clean_timestamp = timestamp.replace('T', ' ').replace('Z', '')
        if '.' in clean_timestamp:
            parts = clean_timestamp.split('.')
            if len(parts[1]) > 3:
                clean_timestamp = parts[0] + '.' + parts[1][:3]

        columns = cls.FULL_COLUMNS if include_raw else cls.LIGHT_COLUMNS

        # Use a small window to handle timestamp precision issues
        query = f"""
        SELECT {columns}
        FROM syslogs
        WHERE {device_where}
          AND timestamp >= toDateTime64('{clean_timestamp}', 3) - INTERVAL 1 SECOND
          AND timestamp <= toDateTime64('{clean_timestamp}', 3) + INTERVAL 1 SECOND
        ORDER BY timestamp ASC
        LIMIT 1
        """

        result = list(client.query(query).named_results())
        return result[0] if result else None

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

    # ── Indexed column mappings for PREWHERE / bloom_filter optimization ──
    # These columns have dedicated bloom_filter or minmax indexes on the syslogs table.
    # When filtering by these fields with '=' operator, use the raw column directly
    # (NOT wrapped in lower()/if()) so ClickHouse can leverage data-skipping indexes.
    _INDEXED_STRING_COLUMNS = {
        'policyname': 'policyname',
        'rule': 'policyname',
        'action': 'action',
        'application': 'application',
        'app': 'application',
        'log_type': 'log_type',
        'session_end_reason': 'session_end_reason',
        'threat_id': 'threat_id',
        'src_zone': 'src_zone',
        'srczone': 'src_zone',
        'dst_zone': 'dst_zone',
        'dstzone': 'dst_zone',
    }

    # Numeric indexed columns (minmax indexes)
    _INDEXED_NUMERIC_COLUMNS = {
        'srcport': 'srcport',
        'dstport': 'dstport',
        'src_port': 'srcport',
        'dst_port': 'dstport',
    }

    @classmethod
    def _build_indexed_prewhere(cls, query_text: Optional[str]) -> List[str]:
        """
        Extract conditions for indexed columns from query_text for PREWHERE.
        Returns list of SQL conditions that use direct column references,
        enabling ClickHouse bloom_filter / minmax indexes to skip granules.
        """
        if not query_text:
            return []

        terms = cls._parse_advanced_query(query_text)
        conditions = []

        for term in terms:
            if term['type'] != 'field':
                continue
            field = term['field']
            operator = term.get('operator', '=')
            value = term['value']
            negated = term['negated']

            # String indexed columns (bloom_filter)
            if field in cls._INDEXED_STRING_COLUMNS and operator == '=':
                col = cls._INDEXED_STRING_COLUMNS[field]
                safe_val = value.replace("'", "''")

                if '|' in value:
                    or_vals = [v.strip().replace("'", "''") for v in value.split('|')]
                    cond = "(" + " OR ".join(f"{col} = '{v}'" for v in or_vals) + ")"
                else:
                    cond = f"{col} = '{safe_val}'"

                if negated:
                    cond = f"NOT ({cond})"
                conditions.append(cond)

            # Numeric indexed columns (minmax)
            elif field in cls._INDEXED_NUMERIC_COLUMNS and operator in ('=', '>', '>=', '<', '<='):
                col = cls._INDEXED_NUMERIC_COLUMNS[field]
                # Handle port ranges and single values
                if operator == '=' and '-' in value:
                    parts = value.split('-')
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        cond = f"({col} >= {parts[0]} AND {col} <= {parts[1]})"
                        if negated:
                            cond = f"NOT {cond}"
                        conditions.append(cond)
                elif value.isdigit():
                    num_val = int(value)
                    if operator == '=' and not negated:
                        conditions.append(f"{col} = {num_val}")
                    elif operator == '=' and negated:
                        conditions.append(f"{col} != {num_val}")
                    else:
                        conditions.append(f"{col} {operator} {num_val}")

        return conditions

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

        # ── Fast-path: indexed string columns (bloom_filter) ──
        # Use direct column comparison so ClickHouse data-skipping indexes work.
        if field in cls._INDEXED_STRING_COLUMNS:
            col = cls._INDEXED_STRING_COLUMNS[field]

            # Handle OR logic (e.g., action:accept|allow|close)
            if '|' in value and operator == '=':
                or_values = [v.strip().replace("'", "''") for v in value.split('|')]
                or_conditions = [f"{col} = '{v}'" for v in or_values]
                combined = f"({' OR '.join(or_conditions)})"
                if negated:
                    return f"NOT {combined}"
                return combined

            # Handle contains/like operator (~)
            if operator == '~':
                like_value = safe_value.replace('*', '%')
                if '%' not in like_value:
                    like_value = f"%{like_value}%"
                if negated:
                    return f"{col} NOT ILIKE '{like_value}'"
                return f"{col} ILIKE '{like_value}'"

            # Handle comparison operators
            if operator in ('>', '>=', '<', '<='):
                return f"{col} {operator} '{safe_value}'"

            # Standard equality — case-sensitive for index utilization
            if negated:
                return f"{col} != '{safe_value}'"
            return f"{col} = '{safe_value}'"

        # ── Fast-path: indexed numeric columns (minmax) ──
        if field in cls._INDEXED_NUMERIC_COLUMNS:
            col = cls._INDEXED_NUMERIC_COLUMNS[field]

            # Handle port ranges (e.g., 80-443)
            if operator == '=' and '-' in value:
                parts = value.split('-')
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    cond = f"({col} >= {parts[0]} AND {col} <= {parts[1]})"
                    if negated:
                        return f"NOT {cond}"
                    return cond

            # Numeric comparison
            try:
                num_val = int(value)
                if operator in ('>', '>=', '<', '<='):
                    return f"{col} {operator} {num_val}"
                if negated:
                    return f"{col} != {num_val}"
                return f"{col} = {num_val}"
            except ValueError:
                pass  # Fall through to field_mapping for non-numeric values

        # Field mapping for normalized and vendor-specific fields
        # Uses indexed columns where available, with fallback to parsed_data
        field_mapping = {
            # Common normalized fields - use indexed column first, then parsed_data
            'srcip': "if(srcip != '', srcip, if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip']))",
            'dstip': "if(dstip != '', dstip, if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip']))",
            'srcport': "if(parsed_data['srcport'] != '', parsed_data['srcport'], parsed_data['src_port'])",
            'dstport': "if(parsed_data['dstport'] != '', parsed_data['dstport'], parsed_data['dst_port'])",
            'action': "if(action != '', action, parsed_data['action'])",
            'policyname': "if(policyname != '', policyname, if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule']))",
            'rule': "if(policyname != '', policyname, if(parsed_data['rule'] != '', parsed_data['rule'], parsed_data['policyname']))",
            'proto': "if(parsed_data['proto'] != '', parsed_data['proto'], parsed_data['protocol'])",
            # Use indexed application column
            'app': "if(application != '', application, if(parsed_data['app'] != '', parsed_data['app'], parsed_data['application']))",
            'application': "if(application != '', application, if(parsed_data['application'] != '', parsed_data['application'], parsed_data['app']))",
            'srcintf': "if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if'])",
            'dstintf': "if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if'])",
            # Use indexed zone columns
            'srczone': "if(src_zone != '', src_zone, if(parsed_data['srczone'] != '', parsed_data['srczone'], parsed_data['src_zone']))",
            'dstzone': "if(dst_zone != '', dst_zone, if(parsed_data['dstzone'] != '', parsed_data['dstzone'], parsed_data['dst_zone']))",
            'src_zone': "if(src_zone != '', src_zone, if(parsed_data['src_zone'] != '', parsed_data['src_zone'], parsed_data['srczone']))",
            'dst_zone': "if(dst_zone != '', dst_zone, if(parsed_data['dst_zone'] != '', parsed_data['dst_zone'], parsed_data['dstzone']))",
            'srcuser': "if(parsed_data['srcuser'] != '', parsed_data['srcuser'], parsed_data['src_user'])",
            'dstuser': "if(parsed_data['dstuser'] != '', parsed_data['dstuser'], parsed_data['dst_user'])",
            # Use indexed log_type column
            'log_type': "if(log_type != '', log_type, parsed_data['log_type'])",
            'type': "if(log_type != '', log_type, parsed_data['type'])",
            # Use indexed session_end_reason column
            'session_end_reason': "if(session_end_reason != '', session_end_reason, parsed_data['session_end_reason'])",
            # Use indexed threat_id column
            'threat_id': "if(threat_id != '', threat_id, parsed_data['threat_id'])",
            'sessionid': "if(parsed_data['sessionid'] != '', parsed_data['sessionid'], parsed_data['session_id'])",
            'duration': "if(parsed_data['duration'] != '', parsed_data['duration'], parsed_data['elapsed_time'])",
            'sentbyte': "if(parsed_data['sentbyte'] != '', parsed_data['sentbyte'], parsed_data['bytes_sent'])",
            'rcvdbyte': "if(parsed_data['rcvdbyte'] != '', parsed_data['rcvdbyte'], parsed_data['bytes_recv'])",
            'srccountry': "if(parsed_data['srccountry'] != '', parsed_data['srccountry'], parsed_data['src_location'])",
            'dstcountry': "if(parsed_data['dstcountry'] != '', parsed_data['dstcountry'], parsed_data['dst_location'])",
            # Fortinet-specific
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
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
            'device': cls._DEVICE_DISPLAY_EXPR,
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

    @staticmethod
    def _parse_device_id(device_str: str):
        """Parse a device identifier like '192.168.47.1_WAN' into (ip, vdom).
        Returns (ip, '') if no VDOM suffix."""
        import re
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)_(.+)$', device_str)
        if m:
            return m.group(1), m.group(2)
        return device_str, ''

    @staticmethod
    def _device_where(device_str: str) -> str:
        """Build a WHERE fragment for a device identifier (IP or IP_VDOM)."""
        import re
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)_(.+)$', device_str)
        if m:
            ip, vdom = m.group(1), m.group(2).replace("'", "''")
            return f"device_ip = toIPv4('{ip}') AND vdom = '{vdom}'"
        safe = device_str.replace("'", "''")
        return f"toString(device_ip) = '{safe}'"

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
            # Parse device identifiers: "192.168.47.1_WAN" -> IP + VDOM filter
            import re
            ip_only = []
            ip_vdom_pairs = []
            for dev in device_ips:
                m = re.match(r'^(\d+\.\d+\.\d+\.\d+)_(.+)$', dev)
                if m:
                    ip_vdom_pairs.append((m.group(1), m.group(2)))
                else:
                    ip_only.append(dev)

            device_conditions = []
            if ip_only:
                formatted = ", ".join([f"toIPv4('{ip}')" for ip in ip_only])
                device_conditions.append(f"device_ip IN ({formatted})")
            for ip, vdom in ip_vdom_pairs:
                safe_vdom = vdom.replace("'", "''")
                device_conditions.append(f"(device_ip = toIPv4('{ip}') AND vdom = '{safe_vdom}')")

            if len(device_conditions) == 1:
                where_clauses.append(device_conditions[0])
            else:
                where_clauses.append("(" + " OR ".join(device_conditions) + ")")

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

    # Light columns for fast queries (excludes only 'raw' - the heaviest field)
    # Keeps parsed_data as it's needed for detail panel display
    LIGHT_COLUMNS = "timestamp, device_ip, vdom, facility, severity, message, srcip, dstip, srcport, dstport, proto, action, policyname, log_type, application, src_zone, dst_zone, session_end_reason, threat_id, parsed_data"
    # Full columns including raw message
    FULL_COLUMNS = "timestamp, device_ip, vdom, facility, severity, message, raw, srcip, dstip, srcport, dstport, proto, action, policyname, log_type, application, src_zone, dst_zone, session_end_reason, threat_id, parsed_data"

    # Expression to compose device display name: IP_VDOM or just IP
    _DEVICE_DISPLAY_EXPR = "if(vdom != '', concat(toString(device_ip), '_', vdom), toString(device_ip))"

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
        default_hours: int = 1,
        include_raw: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Search logs with advanced filtering. Defaults to last 1 hour for performance.

        Args:
            include_raw: If False (default), excludes 'raw' and 'parsed_data' columns
                        for faster queries. Set to True to include full log data.
        """
        client = cls.get_client()

        # Build time filter + indexed field conditions for PREWHERE optimization
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

        # Push indexed field filters to PREWHERE (bloom_filter/minmax index utilization)
        prewhere_parts.extend(cls._build_indexed_prewhere(query_text))

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)

        # Use PREWHERE for time + indexed fields (allows skipping data blocks early)
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        # Use light columns by default for performance (excludes raw, parsed_data)
        columns = cls.FULL_COLUMNS if include_raw else cls.LIGHT_COLUMNS

        query = f"""
        SELECT {columns}
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

        # Build time filter + indexed field conditions for PREWHERE optimization
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

        # Push indexed field filters to PREWHERE (bloom_filter/minmax index utilization)
        prewhere_parts.extend(cls._build_indexed_prewhere(query_text))

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)

        # Use PREWHERE for time + indexed fields
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

    # SQL expression to compute /24 subnet from srcip column
    _SUBNET24_EXPR = "if(srcip = '', '', concat(IPv4NumToString(toUInt32(bitAnd(IPv4StringToNumOrDefault(srcip), 4294967040))), '/24'))"

    @classmethod
    def _build_agg_columns(cls, group_by_fields: List[str], subnet_rollup: bool = False):
        """
        Build SELECT columns and GROUP BY columns for aggregate queries.
        When subnet_rollup=True and srcip is grouped, uses /24 subnet expression.
        Returns (select_cols_str, group_by_cols_str, subnet_extra_str).
        """
        select_cols = []
        group_cols = []
        has_subnet = False

        for field in group_by_fields:
            if field == 'srcip' and subnet_rollup:
                select_cols.append(f"{cls._SUBNET24_EXPR} as src_subnet")
                group_cols.append(cls._SUBNET24_EXPR)
                has_subnet = True
            else:
                select_cols.append(field)
                group_cols.append(field)

        # Extra columns when subnet rollup is active
        subnet_extra = ""
        if has_subnet:
            subnet_extra = ",\n            uniq(srcip) as unique_src_ips,\n            groupUniqArray(5)(srcip) as sample_ips"

        return ", ".join(select_cols), ", ".join(group_cols), subnet_extra

    @classmethod
    def aggregate_logs(
        cls,
        group_by_fields: List[str],
        limit: int = 100,
        offset: int = 0,
        device_ips: Optional[List[str]] = None,
        severities: Optional[List[int]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        facilities: Optional[List[int]] = None,
        default_hours: int = 1,
        subnet_rollup: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Aggregate logs by specified fields (srcip, dstip, dstport).
        Returns grouped rows with event counts, time ranges, and top values.

        When subnet_rollup=True and srcip is in group_by_fields, groups source IPs
        by /24 subnet and includes unique_src_ips count and sample_ips array.
        """
        allowed = {'srcip', 'dstip', 'dstport'}
        group_by_fields = [f for f in group_by_fields if f in allowed]
        if not group_by_fields:
            group_by_fields = ['srcip', 'dstip', 'dstport']

        client = cls.get_client()

        # Build PREWHERE: time filter + indexed field conditions for data-skipping
        prewhere_parts = []
        if start_time is None and end_time is None:
            prewhere_parts.append(f"timestamp > now() - INTERVAL {default_hours} HOUR")
        else:
            if start_time:
                prewhere_parts.append(f"timestamp >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}'")
            if end_time:
                prewhere_parts.append(f"timestamp <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'")

        # Push indexed field filters to PREWHERE (bloom_filter/minmax index utilization)
        prewhere_parts.extend(cls._build_indexed_prewhere(query_text))

        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        select_cols, group_cols, subnet_extra = cls._build_agg_columns(group_by_fields, subnet_rollup)

        query = f"""
        SELECT
            {select_cols},
            count() as event_count,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen,
            any(action) as top_action,
            any(policyname) as top_policy,
            any(application) as top_app,
            uniq(device_ip, vdom) as device_count{subnet_extra}
        FROM syslogs
        PREWHERE {prewhere_clause}
        WHERE {where_sql}
        GROUP BY {group_cols}
        ORDER BY event_count DESC
        LIMIT {limit} OFFSET {offset}
        """

        result = client.query(query).named_results()
        return list(result)

    @classmethod
    def count_aggregate_groups(
        cls,
        group_by_fields: List[str],
        device_ips: Optional[List[str]] = None,
        severities: Optional[List[int]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        query_text: Optional[str] = None,
        facilities: Optional[List[int]] = None,
        default_hours: int = 1,
        max_count: int = 10000,
        subnet_rollup: bool = False,
    ) -> int:
        """
        Count distinct groups for aggregate view.
        Uses uniq() approximation for fast counting (~2-3% accuracy).
        Returns -1 if count exceeds max_count.
        """
        allowed = {'srcip', 'dstip', 'dstport'}
        group_by_fields = [f for f in group_by_fields if f in allowed]
        if not group_by_fields:
            group_by_fields = ['srcip', 'dstip', 'dstport']

        client = cls.get_client()

        prewhere_parts = []
        if start_time is None and end_time is None:
            prewhere_parts.append(f"timestamp > now() - INTERVAL {default_hours} HOUR")
        else:
            if start_time:
                prewhere_parts.append(f"timestamp >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}'")
            if end_time:
                prewhere_parts.append(f"timestamp <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'")

        # Push indexed field filters to PREWHERE (bloom_filter/minmax index utilization)
        prewhere_parts.extend(cls._build_indexed_prewhere(query_text))

        where_sql = cls._build_where_clause(device_ips, severities, None, None, query_text, facilities)
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        # Build uniq() column expressions (same as GROUP BY but as uniq args)
        _, _, _ = cls._build_agg_columns(group_by_fields, subnet_rollup)

        # Use uniq() for approximate count — much faster than GROUP BY subquery
        uniq_cols = []
        for field in group_by_fields:
            if field == 'srcip' and subnet_rollup:
                uniq_cols.append(cls._SUBNET24_EXPR)
            else:
                uniq_cols.append(field)

        query = f"""
        SELECT uniq({', '.join(uniq_cols)}) as approx_groups
        FROM syslogs
        PREWHERE {prewhere_clause}
        WHERE {where_sql}
        """

        result = client.query(query).result_rows
        count = result[0][0] if result else 0
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

        # Build time filter + indexed field conditions for PREWHERE optimization
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

        # Push indexed field filters to PREWHERE (bloom_filter/minmax index utilization)
        prewhere_parts.extend(cls._build_indexed_prewhere(query_text))

        # Build additional WHERE conditions (without time filters)
        where_sql = cls._build_where_clause(device_ips, None, None, None, query_text, None)

        # Use PREWHERE for time filter + indexed fields
        prewhere_clause = " AND ".join(prewhere_parts) if prewhere_parts else "1=1"

        query = f"""
        SELECT
            count() as total_logs,
            uniq(device_ip, vdom) as unique_devices,
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
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
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
            {cls._DEVICE_DISPLAY_EXPR} as device_ip,
            count() as count,
            max(timestamp) as last_log
        FROM syslogs
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY device_ip, vdom
        ORDER BY count DESC
        LIMIT 20
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_distinct_devices(cls, hours: int = 1) -> List[str]:
        """
        Get list of distinct devices from recent logs.
        Returns VDOM-aware names: '192.168.47.1_WAN' for VDOM devices,
        '10.10.0.1' for non-VDOM devices.

        Cached for 60 seconds to avoid repeated queries on every page load.
        """
        import time
        now = time.time()
        if cls._device_list_cache and (now - cls._device_list_cache_time) < cls._DEVICE_LIST_CACHE_TTL:
            return cls._device_list_cache

        client = cls.get_client()
        # Group by (device_ip, vdom) to treat each VDOM as a separate device
        query = f"""
        SELECT DISTINCT {cls._DEVICE_DISPLAY_EXPR} as device_name
        FROM syslogs
        WHERE timestamp > now() - INTERVAL {hours} HOUR
        ORDER BY device_name
        """
        result = [row[0] for row in client.query(query).result_rows]

        # If no devices found in short window, expand to 24h
        if not result and hours < 24:
            query = f"""
            SELECT DISTINCT {cls._DEVICE_DISPLAY_EXPR} as device_name
            FROM syslogs
            WHERE timestamp > now() - INTERVAL 24 HOUR
            ORDER BY device_name
            """
            result = [row[0] for row in client.query(query).result_rows]

        cls._device_list_cache = result
        cls._device_list_cache_time = now
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
        # Group by (device_ip, vdom) to treat each VDOM as a separate device
        query = f"""
        SELECT
            {cls._DEVICE_DISPLAY_EXPR} as device_ip,
            count() as log_count,
            max(timestamp) as newest_log
        FROM syslogs
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY device_ip, vdom
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
        """Get storage distribution over time for visualization.

        Uses count-based estimation instead of sum(length(raw)) which requires
        decompressing the entire raw column and is very slow (~2s+).
        """
        client = cls.get_client()

        # Estimate avg bytes per row from system tables (fast metadata query)
        try:
            size_query = """
            SELECT sum(data_uncompressed_bytes) / greatest(sum(rows), 1) as avg_row_bytes
            FROM system.parts WHERE table = 'syslogs' AND active = 1
            """
            avg_result = client.query(size_query).result_rows
            avg_bytes = avg_result[0][0] if avg_result and avg_result[0][0] else 500
        except Exception:
            avg_bytes = 500

        query = f"""
        SELECT
            toStartOfHour(timestamp) as hour,
            count() as log_count
        FROM syslogs
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY hour
        ORDER BY hour
        """

        results = list(client.query(query).named_results())
        # Estimate raw_bytes from row count
        for r in results:
            r['raw_bytes'] = int(r['log_count'] * avg_bytes)
        return results

    @classmethod
    def delete_old_logs_for_device(cls, device_ip: str, retention_days: int) -> bool:
        """Delete logs older than retention_days for a specific device."""
        if retention_days <= 0:
            return False  # No deletion for unlimited retention

        client = cls.get_client()

        device_where = cls._device_where(device_ip)
        query = f"""
        ALTER TABLE syslogs DELETE
        WHERE {device_where}
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
        device_where = cls._device_where(device_ip)

        # Use PREWHERE on device_ip (part of primary key) for fast partition pruning
        query = f"""
        SELECT
            countIf(timestamp > now() - INTERVAL 1 DAY) as last_24h,
            countIf(timestamp > now() - INTERVAL 7 DAY AND timestamp <= now() - INTERVAL 1 DAY) as last_week,
            countIf(timestamp > now() - INTERVAL 30 DAY AND timestamp <= now() - INTERVAL 7 DAY) as last_month,
            countIf(timestamp <= now() - INTERVAL 30 DAY) as older,
            count() as total
        FROM syslogs
        PREWHERE {device_where}
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
        PREWHERE timestamp > now() - INTERVAL {hours} HOUR
        GROUP BY minute
        ORDER BY minute
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_total_logs_24h(cls) -> int:
        """Get total log count in last 24 hours."""
        client = cls.get_client()
        query = "SELECT count() FROM syslogs PREWHERE timestamp > now() - INTERVAL 24 HOUR"
        result = client.query(query).result_rows
        return result[0][0] if result else 0

    @classmethod
    def get_unique_devices_count(cls) -> int:
        """Get count of unique devices (last 24h for performance)."""
        client = cls.get_client()
        query = "SELECT uniq(device_ip, vdom) FROM syslogs WHERE timestamp > now() - INTERVAL 24 HOUR"
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
        # Uses indexed columns where available for better performance
        field_mapping = {
            # Use indexed columns first, then fall back to parsed_data
            'srcip': "if(srcip != '', srcip, if(parsed_data['srcip'] != '', parsed_data['srcip'], parsed_data['src_ip']))",
            'dstip': "if(dstip != '', dstip, if(parsed_data['dstip'] != '', parsed_data['dstip'], parsed_data['dst_ip']))",
            'srcport': "if(parsed_data['srcport'] != '', parsed_data['srcport'], parsed_data['src_port'])",
            'dstport': "if(parsed_data['dstport'] != '', parsed_data['dstport'], parsed_data['dst_port'])",
            'action': "if(action != '', action, parsed_data['action'])",
            'policyname': "if(policyname != '', policyname, if(parsed_data['policyname'] != '', parsed_data['policyname'], parsed_data['rule']))",
            'rule': "if(policyname != '', policyname, if(parsed_data['rule'] != '', parsed_data['rule'], parsed_data['policyname']))",
            'proto': "if(parsed_data['proto'] != '', parsed_data['proto'], parsed_data['protocol'])",
            # Use indexed application column
            'app': "if(application != '', application, if(parsed_data['app'] != '', parsed_data['app'], parsed_data['application']))",
            'application': "if(application != '', application, if(parsed_data['application'] != '', parsed_data['application'], parsed_data['app']))",
            'srcintf': "if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if'])",
            'dstintf': "if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if'])",
            'service': "parsed_data['service']",
            'policyid': "parsed_data['policyid']",
            'srccountry': "if(parsed_data['srccountry'] != '', parsed_data['srccountry'], parsed_data['src_location'])",
            'dstcountry': "if(parsed_data['dstcountry'] != '', parsed_data['dstcountry'], parsed_data['dst_location'])",
            'appcat': "if(parsed_data['appcat'] != '', parsed_data['appcat'], parsed_data['category_of_app'])",
            # Use indexed zone columns
            'srczone': "if(src_zone != '', src_zone, if(parsed_data['srczone'] != '', parsed_data['srczone'], parsed_data['src_zone']))",
            'dstzone': "if(dst_zone != '', dst_zone, if(parsed_data['dstzone'] != '', parsed_data['dstzone'], parsed_data['dst_zone']))",
            'src_zone': "if(src_zone != '', src_zone, if(parsed_data['src_zone'] != '', parsed_data['src_zone'], parsed_data['srczone']))",
            'dst_zone': "if(dst_zone != '', dst_zone, if(parsed_data['dst_zone'] != '', parsed_data['dst_zone'], parsed_data['dstzone']))",
            'srcuser': "if(parsed_data['srcuser'] != '', parsed_data['srcuser'], parsed_data['src_user'])",
            'dstuser': "if(parsed_data['dstuser'] != '', parsed_data['dstuser'], parsed_data['dst_user'])",
            # Use indexed log_type column
            'log_type': "if(log_type != '', log_type, parsed_data['log_type'])",
            'type': "if(log_type != '', log_type, parsed_data['type'])",
            'subtype': "parsed_data['subtype']",
            'device': cls._DEVICE_DISPLAY_EXPR,
            'device_name': "if(parsed_data['device_name'] != '', parsed_data['device_name'], parsed_data['devname'])",
            # Use indexed session_end_reason and threat_id columns
            'session_end_reason': "if(session_end_reason != '', session_end_reason, parsed_data['session_end_reason'])",
            'threat_id': "if(threat_id != '', threat_id, parsed_data['threat_id'])",
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
            {cls._DEVICE_DISPLAY_EXPR} as device_ip,
            severity,
            parsed_data,
            action,
            srcip,
            dstip,
            toString(srcport) as srcport,
            toString(dstport) as dstport,
            toString(proto) as proto,
            if(src_zone != '', src_zone, if(parsed_data['srcintf'] != '', parsed_data['srcintf'], parsed_data['inbound_if'])) as srcintf,
            if(dst_zone != '', dst_zone, if(parsed_data['dstintf'] != '', parsed_data['dstintf'], parsed_data['outbound_if'])) as dstintf,
            parsed_data['policyid'] as policyid,
            policyname,
            parsed_data['service'] as service,
            if(parsed_data['duration'] != '', parsed_data['duration'], parsed_data['elapsed_time']) as duration,
            if(parsed_data['sentbyte'] != '', parsed_data['sentbyte'], parsed_data['bytes_sent']) as sentbyte,
            if(parsed_data['rcvdbyte'] != '', parsed_data['rcvdbyte'], parsed_data['bytes_recv']) as rcvdbyte,
            session_end_reason
        FROM syslogs
        PREWHERE timestamp BETWEEN
            toDateTime64('{ts_str}', 3) - INTERVAL {time_window_seconds} SECOND
            AND toDateTime64('{ts_str}', 3) + INTERVAL {time_window_seconds} SECOND
        WHERE
            srcip = '{safe_srcip}'
            AND dstip = '{safe_dstip}'
            AND (toString(dstport) = '{safe_dstport}' OR parsed_data['dstport'] = '{safe_dstport}' OR parsed_data['dst_port'] = '{safe_dstport}')
            AND (toString(proto) = '{safe_proto}' OR parsed_data['proto'] = '{safe_proto}' OR parsed_data['protocol'] = '{safe_proto}')
        ORDER BY timestamp ASC
        """

        result = list(client.query(query).named_results())
        return result

    # Device list cache for performance (used on every log page load)
    _device_list_cache: List[str] = []
    _device_list_cache_time: float = 0
    _DEVICE_LIST_CACHE_TTL: int = 60  # 60 seconds - devices rarely change

    # Dashboard cache for performance
    _dashboard_cache: Dict[str, Any] = {}
    _dashboard_cache_time: float = 0
    _DASHBOARD_CACHE_TTL: int = 120  # Cache for 2 minutes (dashboard data is 24h aggregates, doesn't need to be real-time)

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
            'devices': f"""
                SELECT {cls._DEVICE_DISPLAY_EXPR} as device, count() as log_count, max(timestamp) as last_seen,
                    countIf(severity <= 3) as critical_count, 0 as denied_count
                FROM syslogs
                WHERE timestamp > now() - INTERVAL 24 HOUR
                GROUP BY device_ip, vdom ORDER BY log_count DESC
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
        device_where = cls._device_where(device_ip)

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
            {cls._DEVICE_DISPLAY_EXPR} as device_ip,
            severity,
            parsed_data
        FROM syslogs
        WHERE
            {device_where}
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

    # ============================================================
    # System Monitoring Methods
    # ============================================================

    @classmethod
    def get_all_table_sizes(cls) -> List[Dict[str, Any]]:
        """
        Get sizes of all ClickHouse tables for system monitoring.
        Returns list sorted by size descending.
        """
        client = cls.get_client()

        query = """
        SELECT
            database,
            table,
            sum(bytes_on_disk) AS total_bytes,
            sum(rows) AS total_rows,
            formatReadableSize(sum(bytes_on_disk)) AS size_readable
        FROM system.parts
        WHERE active
        GROUP BY database, table
        ORDER BY total_bytes DESC
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_database_storage_summary(cls) -> Dict[str, Any]:
        """
        Get summary of ClickHouse storage usage.
        """
        client = cls.get_client()

        query = """
        SELECT
            database,
            sum(bytes_on_disk) AS total_bytes,
            sum(rows) AS total_rows,
            formatReadableSize(sum(bytes_on_disk)) AS size_readable
        FROM system.parts
        WHERE active
        GROUP BY database
        ORDER BY total_bytes DESC
        """

        results = list(client.query(query).named_results())
        total_bytes = sum(r['total_bytes'] for r in results)

        return {
            'databases': results,
            'total_bytes': total_bytes,
            'total_readable': cls._format_bytes(total_bytes)
        }

    @classmethod
    def _format_bytes(cls, size: int) -> str:
        """Format bytes to human readable string."""
        if size < 1024:
            return f"{size} B"
        for unit in ['KB', 'MB', 'GB', 'TB']:
            size /= 1024.0
            if size < 1024.0:
                if size < 10:
                    return f"{size:.2f} {unit}"
                elif size < 100:
                    return f"{size:.1f} {unit}"
                else:
                    return f"{size:.0f} {unit}"
        return f"{size:.1f} PB"

    @classmethod
    def get_system_table_sizes(cls) -> List[Dict[str, Any]]:
        """
        Get sizes of system tables specifically.
        These are the tables that can be truncated during cleanup.
        """
        client = cls.get_client()

        query = """
        SELECT
            database,
            table,
            sum(bytes_on_disk) AS total_bytes,
            sum(rows) AS total_rows,
            formatReadableSize(sum(bytes_on_disk)) AS size_readable
        FROM system.parts
        WHERE active AND database = 'system'
        GROUP BY database, table
        ORDER BY total_bytes DESC
        """

        return list(client.query(query).named_results())

    @classmethod
    def truncate_system_table(cls, table: str) -> bool:
        """
        Truncate a system table to free up space.
        Only allows truncation of safe system log tables.
        """
        safe_tables = [
            'trace_log', 'text_log', 'query_log', 'metric_log',
            'part_log', 'asynchronous_metric_log', 'processors_profile_log',
            'query_metric_log', 'asynchronous_insert_log', 'error_log'
        ]

        if table not in safe_tables:
            logger.warning(f"Attempted to truncate non-safe table: {table}")
            return False

        try:
            client = cls.get_client()
            client.command(f"TRUNCATE TABLE system.{table}")
            logger.info(f"Truncated system.{table}")
            return True
        except Exception as e:
            logger.error(f"Failed to truncate system.{table}: {e}")
            return False

    @classmethod
    def get_syslogs_partition_info(cls) -> List[Dict[str, Any]]:
        """
        Get partition information for the syslogs table.
        Shows data distribution by month.
        """
        client = cls.get_client()

        query = """
        SELECT
            partition,
            sum(bytes_on_disk) AS total_bytes,
            sum(rows) AS total_rows,
            formatReadableSize(sum(bytes_on_disk)) AS size_readable,
            min(min_time) AS min_time,
            max(max_time) AS max_time
        FROM system.parts
        WHERE active AND table = 'syslogs'
        GROUP BY partition
        ORDER BY partition DESC
        """

        return list(client.query(query).named_results())

    @classmethod
    def get_cleanup_status(cls) -> Dict[str, Any]:
        """
        Get status of ongoing mutations (deletions/optimizations).
        """
        client = cls.get_client()

        query = """
        SELECT
            database,
            table,
            mutation_id,
            command,
            create_time,
            is_done,
            latest_fail_reason
        FROM system.mutations
        WHERE NOT is_done
        ORDER BY create_time DESC
        LIMIT 20
        """

        mutations = list(client.query(query).named_results())

        return {
            'pending_mutations': len(mutations),
            'mutations': mutations
        }

    # ============================================================
    # Storage Quota Management Methods
    # ============================================================

    @classmethod
    def get_syslogs_storage_info(cls) -> Dict[str, Any]:
        """
        Get detailed storage information for the syslogs table.
        Used for storage quota monitoring and auto-cleanup decisions.
        """
        client = cls.get_client()

        query = """
        SELECT
            sum(bytes_on_disk) AS total_bytes,
            sum(rows) AS total_rows,
            formatReadableSize(sum(bytes_on_disk)) AS size_readable,
            min(min_time) AS oldest_data,
            max(max_time) AS newest_data,
            count() AS partition_count
        FROM system.parts
        WHERE active AND table = 'syslogs' AND database = 'default'
        """

        result = client.query(query).named_results()
        if result:
            data = list(result)[0]
            return {
                'total_bytes': data['total_bytes'] or 0,
                'total_rows': data['total_rows'] or 0,
                'size_readable': data['size_readable'] or '0 B',
                'size_gb': round((data['total_bytes'] or 0) / (1024**3), 2),
                'oldest_data': data['oldest_data'],
                'newest_data': data['newest_data'],
                'partition_count': data['partition_count'] or 0
            }
        return {
            'total_bytes': 0,
            'total_rows': 0,
            'size_readable': '0 B',
            'size_gb': 0.0,
            'oldest_data': None,
            'newest_data': None,
            'partition_count': 0
        }

    @classmethod
    def get_syslogs_date_range_info(cls) -> List[Dict[str, Any]]:
        """
        Get storage breakdown by date range for intelligent cleanup.
        Returns data grouped by day with size information.
        """
        client = cls.get_client()

        query = """
        SELECT
            toDate(timestamp) AS log_date,
            count() AS row_count,
            sum(length(raw)) AS estimated_bytes
        FROM syslogs
        WHERE timestamp > now() - INTERVAL 90 DAY
        GROUP BY log_date
        ORDER BY log_date ASC
        """

        try:
            return list(client.query(query).named_results())
        except Exception as e:
            logger.error(f"Failed to get date range info: {e}")
            return []

    @classmethod
    def estimate_deletion_size(cls, days_to_keep: int) -> Dict[str, Any]:
        """
        Estimate how much data would be deleted if we keep only the last N days.
        Helps in determining the right deletion threshold.
        """
        client = cls.get_client()

        query = f"""
        SELECT
            count() AS rows_to_delete,
            sum(length(raw)) AS estimated_bytes
        FROM syslogs
        WHERE timestamp < now() - INTERVAL {days_to_keep} DAY
        """

        result = client.query(query).named_results()
        if result:
            data = list(result)[0]
            return {
                'rows_to_delete': data['rows_to_delete'] or 0,
                'estimated_bytes': data['estimated_bytes'] or 0,
                'estimated_gb': round((data['estimated_bytes'] or 0) / (1024**3), 2)
            }
        return {'rows_to_delete': 0, 'estimated_bytes': 0, 'estimated_gb': 0.0}

    @classmethod
    def delete_logs_older_than(cls, days: int, batch_size: int = 0) -> Dict[str, Any]:
        """
        Delete syslogs older than specified days.
        Uses ALTER TABLE DELETE for asynchronous mutation.

        Args:
            days: Delete logs older than this many days
            batch_size: Not used for ALTER DELETE (ClickHouse handles internally)

        Returns:
            Dict with status, mutation_id, and estimated affected rows
        """
        client = cls.get_client()

        # First estimate what will be deleted
        estimate = cls.estimate_deletion_size(days)

        if estimate['rows_to_delete'] == 0:
            return {
                'success': True,
                'message': 'No logs to delete',
                'rows_affected': 0,
                'mutation_id': None
            }

        # Execute deletion
        delete_query = f"""
        ALTER TABLE syslogs DELETE WHERE timestamp < now() - INTERVAL {days} DAY
        """

        try:
            client.command(delete_query)
            logger.info(f"Initiated deletion of logs older than {days} days (est. {estimate['rows_to_delete']} rows)")

            # Get the mutation ID
            mutation_query = """
            SELECT mutation_id
            FROM system.mutations
            WHERE table = 'syslogs' AND NOT is_done
            ORDER BY create_time DESC
            LIMIT 1
            """
            mutation_result = list(client.query(mutation_query).named_results())
            mutation_id = mutation_result[0]['mutation_id'] if mutation_result else None

            return {
                'success': True,
                'message': f'Deletion initiated for logs older than {days} days',
                'rows_affected': estimate['rows_to_delete'],
                'estimated_freed_gb': estimate['estimated_gb'],
                'mutation_id': mutation_id
            }
        except Exception as e:
            logger.error(f"Failed to delete old logs: {e}")
            return {
                'success': False,
                'message': str(e),
                'rows_affected': 0,
                'mutation_id': None
            }

    @classmethod
    def delete_logs_to_reach_target_size(cls, target_size_gb: float, min_retention_days: int = 7) -> Dict[str, Any]:
        """
        Intelligently delete old logs to reach a target storage size.
        Uses binary search to find the optimal retention period.

        Args:
            target_size_gb: Target size in GB
            min_retention_days: Never delete logs newer than this

        Returns:
            Dict with status and details of what was deleted
        """
        current_info = cls.get_syslogs_storage_info()
        current_size_gb = current_info['size_gb']

        if current_size_gb <= target_size_gb:
            return {
                'success': True,
                'message': f'Current size ({current_size_gb:.2f} GB) is already below target ({target_size_gb:.2f} GB)',
                'action_taken': False,
                'current_size_gb': current_size_gb,
                'target_size_gb': target_size_gb
            }

        size_to_free_gb = current_size_gb - target_size_gb
        logger.info(f"Need to free {size_to_free_gb:.2f} GB to reach target of {target_size_gb:.2f} GB")

        # Binary search to find optimal retention days
        # Start with reasonable bounds
        low_days = min_retention_days
        high_days = 365

        optimal_days = high_days

        for _ in range(10):  # Max 10 iterations
            mid_days = (low_days + high_days) // 2
            estimate = cls.estimate_deletion_size(mid_days)

            if estimate['estimated_gb'] >= size_to_free_gb:
                optimal_days = mid_days
                low_days = mid_days + 1
            else:
                high_days = mid_days - 1

            if low_days > high_days:
                break

        # Make sure we don't go below minimum retention
        if optimal_days < min_retention_days:
            return {
                'success': False,
                'message': f'Cannot reach target without violating minimum retention of {min_retention_days} days',
                'action_taken': False,
                'current_size_gb': current_size_gb,
                'target_size_gb': target_size_gb,
                'min_retention_days': min_retention_days
            }

        # Execute the deletion
        result = cls.delete_logs_older_than(optimal_days)

        return {
            'success': result['success'],
            'message': result['message'],
            'action_taken': True,
            'retention_days_used': optimal_days,
            'current_size_gb': current_size_gb,
            'target_size_gb': target_size_gb,
            'estimated_freed_gb': result.get('estimated_freed_gb', 0),
            'rows_affected': result.get('rows_affected', 0),
            'mutation_id': result.get('mutation_id')
        }

    @classmethod
    def get_oldest_log_age_days(cls) -> int:
        """Get the age of the oldest log entry in days."""
        client = cls.get_client()

        query = """
        SELECT dateDiff('day', min(timestamp), now()) AS age_days
        FROM syslogs
        """

        try:
            result = list(client.query(query).named_results())
            if result and result[0]['age_days']:
                return int(result[0]['age_days'])
        except Exception as e:
            logger.error(f"Failed to get oldest log age: {e}")

        return 0

    @staticmethod
    def _build_time_prewhere(start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None,
                             default_hours: int = 24) -> str:
        """Build the timestamp portion of a PREWHERE clause."""
        parts = []
        if start_time is None and end_time is None:
            parts.append(f"timestamp > now() - INTERVAL {int(default_hours)} HOUR")
        else:
            if start_time:
                parts.append(f"timestamp >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}'")
            if end_time:
                parts.append(f"timestamp <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'")
        return " AND ".join(parts) if parts else "1=1"

    @staticmethod
    def _compute_specificity(distinct_port_count: int) -> Tuple[str, int]:
        """Map port diversity to a human label and numeric score."""
        if distinct_port_count <= 1:
            return ("specific", 100)
        elif distinct_port_count <= 5:
            return ("narrow", 80)
        elif distinct_port_count <= 15:
            return ("service-group", 50)
        elif distinct_port_count <= 50:
            return ("broad", 20)
        else:
            return ("any", 5)

    @classmethod
    def policy_lookup(
        cls,
        dstip: str,
        dstport: int,
        srcip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        default_hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Look up existing firewall policies for a destination IP:port.

        Runs 4 sequential queries against indexed columns (PREWHERE) for
        sub-second performance even on 250M+ row tables.
        """
        # --- Input validation ---
        ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_re.match(dstip):
            raise ValueError(f"Invalid destination IP: {dstip}")
        dstport = int(dstport)
        if not (0 <= dstport <= 65535):
            raise ValueError(f"Invalid port: {dstport}")
        if srcip and not ip_re.match(srcip):
            raise ValueError(f"Invalid source IP: {srcip}")

        # Escape single quotes for SQL safety
        dstip_safe = dstip.replace("'", "")
        srcip_safe = srcip.replace("'", "") if srcip else None

        client = cls.get_client()
        time_clause = cls._build_time_prewhere(start_time, end_time, default_hours)
        device_expr = cls._DEVICE_DISPLAY_EXPR

        # ── Query 1: Allowed traffic ──
        srcip_where = f"AND srcip = '{srcip_safe}'" if srcip_safe else ""
        q_allowed = f"""
        SELECT
            {device_expr} as device_display,
            toString(device_ip) as device_ip_str,
            vdom,
            policyname,
            action,
            application,
            src_zone,
            dst_zone,
            count()               as event_count,
            uniq(srcip)           as unique_src_count,
            groupUniqArray(10)(toString(srcip)) as sample_sources,
            min(timestamp)        as first_seen,
            max(timestamp)        as last_seen
        FROM syslogs
        PREWHERE {time_clause}
            AND dstip = '{dstip_safe}'
            AND dstport = {dstport}
            AND action IN ('accept','allow','pass','close','client-rst','server-rst')
        WHERE 1=1 {srcip_where}
        GROUP BY device_ip, vdom, policyname, action, application, src_zone, dst_zone
        ORDER BY event_count DESC
        LIMIT 200
        """
        allowed_rows = list(client.query(q_allowed).named_results())

        # ── Query 2: Denied traffic (never filtered by srcip — show ALL denies) ──
        q_denied = f"""
        SELECT
            {device_expr} as device_display,
            toString(device_ip) as device_ip_str,
            vdom,
            policyname,
            action,
            application,
            src_zone,
            dst_zone,
            count()               as event_count,
            uniq(srcip)           as unique_src_count,
            groupUniqArray(5)(toString(srcip)) as sample_sources,
            min(timestamp)        as first_seen,
            max(timestamp)        as last_seen
        FROM syslogs
        PREWHERE {time_clause}
            AND dstip = '{dstip_safe}'
            AND dstport = {dstport}
            AND action IN ('deny','drop','block','reject','blocked','reset-both')
        GROUP BY device_ip, vdom, policyname, action, application, src_zone, dst_zone
        ORDER BY event_count DESC
        LIMIT 100
        """
        denied_rows = list(client.query(q_denied).named_results())

        # ── Query 3: Port specificity per policy ──
        # For each allowed policy, how many distinct ports does it serve?
        policy_keys = set()
        for r in allowed_rows:
            policy_keys.add((r['device_ip_str'], r['vdom'], r['policyname']))

        specificity_map: Dict[tuple, Tuple[str, int]] = {}
        if policy_keys:
            # Build an IN clause for the (device_ip, vdom, policyname) tuples
            in_values = ", ".join(
                f"(toIPv4('{k[0]}'), '{k[1].replace(chr(39), '')}', '{k[2].replace(chr(39), '')}')"
                for k in policy_keys
            )
            q_specificity = f"""
            SELECT
                toString(device_ip) as device_ip_str,
                vdom,
                policyname,
                uniq(dstport) as distinct_ports
            FROM syslogs
            PREWHERE {time_clause}
                AND dstip = '{dstip_safe}'
                AND action IN ('accept','allow','pass','close','client-rst','server-rst')
            WHERE (device_ip, vdom, policyname) IN ({in_values})
            GROUP BY device_ip, vdom, policyname
            """
            for row in client.query(q_specificity).named_results():
                key = (row['device_ip_str'], row['vdom'], row['policyname'])
                specificity_map[key] = cls._compute_specificity(row['distinct_ports'])

        # ── Query 4: Source coverage (only when srcip provided) ──
        source_coverage: Dict[tuple, bool] = {}
        if srcip_safe and policy_keys:
            q_source = f"""
            SELECT
                toString(device_ip) as device_ip_str,
                vdom,
                policyname,
                count() as src_events
            FROM syslogs
            PREWHERE {time_clause}
                AND dstip = '{dstip_safe}'
                AND action IN ('accept','allow','pass','close','client-rst','server-rst')
            WHERE srcip = '{srcip_safe}'
                AND (device_ip, vdom, policyname) IN ({in_values})
            GROUP BY device_ip, vdom, policyname
            """
            for row in client.query(q_source).named_results():
                key = (row['device_ip_str'], row['vdom'], row['policyname'])
                source_coverage[key] = row['src_events'] > 0

        # ── Post-processing ──
        allowed_devices = set()
        denied_devices = set()

        for r in allowed_rows:
            key = (r['device_ip_str'], r['vdom'], r['policyname'])
            label, score = specificity_map.get(key, ("unknown", 0))
            r['specificity_label'] = label
            r['specificity_score'] = score
            r['source_covered'] = source_coverage.get(key, None)
            # Convert datetime objects to strings for template
            r['first_seen'] = str(r['first_seen']) if r['first_seen'] else ''
            r['last_seen'] = str(r['last_seen']) if r['last_seen'] else ''
            r['sample_sources'] = list(r.get('sample_sources', []))
            allowed_devices.add(r['device_display'])

        for r in denied_rows:
            r['first_seen'] = str(r['first_seen']) if r['first_seen'] else ''
            r['last_seen'] = str(r['last_seen']) if r['last_seen'] else ''
            r['sample_sources'] = list(r.get('sample_sources', []))
            denied_devices.add(r['device_display'])

        gap_devices = sorted(denied_devices - allowed_devices)

        total_allowed = sum(r['event_count'] for r in allowed_rows)
        total_denied = sum(r['event_count'] for r in denied_rows)

        source_already_covered = None
        if srcip_safe:
            source_already_covered = any(
                source_coverage.get((r['device_ip_str'], r['vdom'], r['policyname']), False)
                for r in allowed_rows
            )

        return {
            "allowed": allowed_rows,
            "denied": denied_rows,
            "gap_devices": gap_devices,
            "summary": {
                "total_devices_checked": len(allowed_devices | denied_devices),
                "devices_with_allow": len(allowed_devices),
                "devices_with_deny_only": len(gap_devices),
                "total_allow_policies": len(allowed_rows),
                "total_allowed_events": total_allowed,
                "total_denied_events": total_denied,
                "source_already_covered": source_already_covered,
            },
        }

    @classmethod
    def optimize_syslogs_table(cls) -> Dict[str, Any]:
        """
        Run OPTIMIZE TABLE to reclaim space after deletions.
        This forces merge of parts and physical deletion of data.
        """
        client = cls.get_client()

        try:
            # Use OPTIMIZE with FINAL to force full merge
            client.command("OPTIMIZE TABLE syslogs FINAL", settings={'receive_timeout': 600})
            logger.info("OPTIMIZE TABLE syslogs FINAL completed")
            return {'success': True, 'message': 'Optimization completed'}
        except Exception as e:
            logger.error(f"Failed to optimize syslogs table: {e}")
            return {'success': False, 'message': str(e)}
