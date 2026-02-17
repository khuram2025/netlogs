"""
High-Performance Syslog Collector for Enterprise Firewall Log Management

Architecture (v2 — production-hardened):
- Zero-allocation UDP receive path: datagram_received() only appends raw bytes
  to a collections.deque (no asyncio.create_task, no locks, no allocations)
- Dedicated batch worker drains the deque, parses, and inserts to ClickHouse
- Reusable ClickHouse client (no per-batch connection overhead)
- Retry with back-off on failed ClickHouse inserts (no silent data loss)
- Large OS-level UDP socket buffer (26 MB) to absorb burst traffic
- Device cache with long TTL; auto-approve unknown devices (never drop)
- IOC matching runs on the batch path, not the per-packet hot path

Performance Targets:
- 500+ EPS sustained (>1 000 EPS burst)
- <0.1 µs per packet in datagram_received (append-only)
- 0% planned log loss (retry on insert failure, overflow warning)
"""

import asyncio
import signal
import socket
import time
import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from ..core.config import settings
from ..db.database import get_database_url
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, DeviceStatus
from .parsers import get_parser

logger = logging.getLogger('syslog_collector')

# Create a dedicated non-echo engine for syslog (avoids SQLAlchemy query logging)
_syslog_engine = create_async_engine(get_database_url(), echo=False, poolclass=NullPool)
_syslog_session_maker = async_sessionmaker(
    _syslog_engine, class_=AsyncSession, expire_on_commit=False
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class CollectorConfig:
    """Syslog collector configuration."""
    host: str = "0.0.0.0"
    port: int = 514
    batch_size: int = 5000
    flush_interval: float = 2.0
    device_cache_ttl: int = 300       # 5 min — devices rarely change
    worker_threads: int = 4
    max_queue_size: int = 500_000     # ~500 K packets before overflow
    metrics_interval: int = 30
    udp_recv_buffer: int = 26_214_400  # 26 MB OS socket buffer
    insert_retries: int = 3
    insert_retry_delay: float = 1.0


# ---------------------------------------------------------------------------
# Device cache (thread-safe via dict atomic reads + TTL)
# ---------------------------------------------------------------------------

@dataclass
class CachedDevice:
    status: str
    parser: str
    cached_at: float

    def is_expired(self, ttl: int) -> bool:
        return (time.time() - self.cached_at) > ttl


class DeviceCache:
    """Thread-safe device cache.  Uses a plain dict which is safe for
    atomic get/set in CPython due to the GIL."""

    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self._cache: Dict[str, CachedDevice] = {}
        self._hits = 0
        self._misses = 0

    def get(self, ip: str) -> Optional[CachedDevice]:
        cached = self._cache.get(ip)
        if cached and not cached.is_expired(self.ttl):
            self._hits += 1
            return cached
        self._misses += 1
        return None

    def set(self, ip: str, status: str, parser: str):
        self._cache[ip] = CachedDevice(status=status, parser=parser, cached_at=time.time())

    def get_stats(self) -> dict:
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            'size': len(self._cache),
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': f"{hit_rate:.1f}%",
        }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class MetricsCollector:
    """Lock-free metrics (single-writer from the batch worker)."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.logs_received = 0
        self.logs_processed = 0
        self.logs_dropped_overflow = 0
        self.logs_dropped_parse = 0
        self.logs_dropped_device = 0
        self.batches_flushed = 0
        self.flush_errors = 0
        self.insert_retries = 0
        self._start_time = time.time()
        self._by_device: Dict[str, int] = defaultdict(int)

    def get_report(self) -> dict:
        elapsed = time.time() - self._start_time
        rate = self.logs_received / elapsed if elapsed > 0 else 0
        total_dropped = self.logs_dropped_overflow + self.logs_dropped_parse + self.logs_dropped_device
        return {
            'elapsed_seconds': int(elapsed),
            'logs_received': self.logs_received,
            'logs_processed': self.logs_processed,
            'total_dropped': total_dropped,
            'dropped_overflow': self.logs_dropped_overflow,
            'dropped_parse': self.logs_dropped_parse,
            'dropped_device': self.logs_dropped_device,
            'drop_pct': f"{total_dropped / self.logs_received * 100:.2f}%" if self.logs_received else "0%",
            'eps': int(rate),
            'batches_flushed': self.batches_flushed,
            'flush_errors': self.flush_errors,
            'insert_retries': self.insert_retries,
            'active_devices': len(self._by_device),
            'top_devices': dict(sorted(self._by_device.items(), key=lambda x: x[1], reverse=True)[:5]),
        }


# ---------------------------------------------------------------------------
# Pre-compiled regex
# ---------------------------------------------------------------------------

PRI_REGEX = re.compile(r'^<(\d{1,3})>(.*)', re.DOTALL)


def parse_syslog_message(data: bytes, device_parser: str) -> Optional[tuple]:
    """
    Parse raw syslog bytes into a structured tuple.
    Returns None on parse failure.
    """
    try:
        decoded = data.decode('utf-8', errors='replace')

        facility = 1
        severity = 6
        message = decoded

        match = PRI_REGEX.match(decoded)
        if match:
            pri = int(match.group(1))
            facility = pri >> 3
            severity = pri & 7
            message = match.group(2).strip()

        parser = get_parser(device_parser)
        parsed_data = parser.parse(message)

        srcip = parsed_data.get('srcip') or parsed_data.get('src_ip', '')
        dstip = parsed_data.get('dstip') or parsed_data.get('dst_ip', '')
        action = parsed_data.get('action', '')
        policyname = parsed_data.get('policyname') or parsed_data.get('rule', '')

        srcport_str = parsed_data.get('srcport') or parsed_data.get('src_port', '0')
        dstport_str = parsed_data.get('dstport') or parsed_data.get('dst_port', '0')
        try:
            srcport = int(srcport_str) if srcport_str else 0
        except (ValueError, TypeError):
            srcport = 0
        try:
            dstport = int(dstport_str) if dstport_str else 0
        except (ValueError, TypeError):
            dstport = 0

        proto_str = parsed_data.get('proto') or parsed_data.get('protocol', '0')
        try:
            proto = int(proto_str) if proto_str else 0
        except (ValueError, TypeError):
            proto = 0

        log_type = parsed_data.get('log_type', '')
        if not log_type:
            fgt_type = parsed_data.get('type', '')
            fgt_subtype = parsed_data.get('subtype', '')
            if fgt_type:
                log_type = f"{fgt_type}/{fgt_subtype}" if fgt_subtype else fgt_type

        application = parsed_data.get('app') or parsed_data.get('application', '')
        src_zone = parsed_data.get('src_zone') or parsed_data.get('srczone') or parsed_data.get('srcintf', '')
        dst_zone = parsed_data.get('dst_zone') or parsed_data.get('dstzone') or parsed_data.get('dstintf', '')
        session_end_reason = parsed_data.get('session_end_reason', '')
        threat_id = parsed_data.get('threat_id', '')
        vdom = parsed_data.get('vd', '') if parsed_data else ''

        return (facility, severity, message, decoded, srcip, dstip, srcport, dstport, proto,
                action, policyname, log_type, application, src_zone, dst_zone,
                session_end_reason, threat_id, vdom, parsed_data)
    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

async def get_or_create_device(ip: str) -> Optional[Tuple[str, str]]:
    """
    Get device (status, parser) from PostgreSQL.
    Auto-creates new devices as APPROVED so logs are never dropped.
    """
    try:
        async with _syslog_session_maker() as session:
            result = await session.execute(
                text("SELECT status, parser FROM devices_device WHERE ip_address = CAST(:ip AS inet)"),
                {"ip": ip}
            )
            row = result.first()

            if row is None:
                # Auto-approve: new devices default to APPROVED with GENERIC parser
                # Admin can change parser type later in the UI
                await session.execute(text(
                    "INSERT INTO devices_device (ip_address, status, parser, retention_days, log_count, created_at, updated_at) "
                    "VALUES (:ip, :status, :parser, :retention, 0, now(), now()) "
                    "ON CONFLICT (ip_address) DO NOTHING"
                ), {
                    'ip': ip,
                    'status': DeviceStatus.APPROVED,
                    'parser': 'GENERIC',
                    'retention': 90,
                })
                await session.commit()
                logger.info(f"New device auto-approved: {ip}")
                return (DeviceStatus.APPROVED, 'GENERIC')

            return (row.status, row.parser)
    except Exception as e:
        logger.error(f"DB error for device {ip}: {e}")
        # On DB error, STILL accept the log with generic parser
        # rather than dropping it
        return (DeviceStatus.APPROVED, 'GENERIC')


async def batch_update_device_stats(updates: Dict[str, dict]):
    """Batch-update device last_log_received and log_count using raw SQL to handle INET type."""
    if not updates:
        return
    try:
        async with _syslog_session_maker() as session:
            for ip, data in updates.items():
                await session.execute(
                    text("""
                        UPDATE devices_device
                        SET updated_at = now(),
                            last_log_received = :last_time,
                            log_count = log_count + :count
                        WHERE ip_address = CAST(:ip AS inet)
                    """),
                    {"last_time": data['last_time'], "count": data['count'], "ip": ip}
                )
            await session.commit()
    except Exception as e:
        logger.error(f"Device stats update failed: {e}")


# ---------------------------------------------------------------------------
# ClickHouse insert with retry
# ---------------------------------------------------------------------------

def flush_to_clickhouse(
    client,
    logs: List[tuple],
    retries: int = 3,
    retry_delay: float = 1.0,
) -> Tuple[bool, int]:
    """
    Insert logs to ClickHouse with retry.
    Returns (success, retry_count).
    """
    if not logs:
        return True, 0

    last_err = None
    for attempt in range(retries):
        try:
            client.insert('syslogs', logs, column_names=[
                'timestamp', 'device_ip', 'facility', 'severity', 'message', 'raw',
                'srcip', 'dstip', 'srcport', 'dstport', 'proto', 'action', 'policyname',
                'log_type', 'application', 'src_zone', 'dst_zone', 'session_end_reason',
                'threat_id', 'vdom', 'parsed_data',
            ])
            return True, attempt
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                logger.warning(f"ClickHouse insert attempt {attempt+1} failed: {e}, retrying...")
                time.sleep(retry_delay * (attempt + 1))
            else:
                logger.error(f"ClickHouse insert FAILED after {retries} attempts: {e}")

    return False, retries


# ---------------------------------------------------------------------------
# UDP Protocol — ultra-lightweight receive path
# ---------------------------------------------------------------------------

class SyslogProtocol(asyncio.DatagramProtocol):
    """
    Minimal UDP handler.  datagram_received() ONLY appends raw bytes + addr
    to a deque.  All parsing and DB work happens in the batch worker.
    """

    def __init__(self, raw_queue: deque, max_size: int, metrics: MetricsCollector):
        self._queue = raw_queue
        self._max_size = max_size
        self._metrics = metrics
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        # Enlarge OS-level UDP receive buffer
        sock = transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 26_214_400)
                actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                logger.info(f"UDP socket receive buffer: {actual:,} bytes")
            except OSError as e:
                logger.warning(f"Could not set SO_RCVBUF: {e}")
        logger.info("UDP transport ready")

    def datagram_received(self, data: bytes, addr: tuple):
        """
        HOT PATH — must be as fast as possible.
        Just append (ip, raw_bytes) to the lock-free deque.
        """
        self._metrics.logs_received += 1
        if len(self._queue) < self._max_size:
            self._queue.append((addr[0], data))
        else:
            self._metrics.logs_dropped_overflow += 1

    def error_received(self, exc):
        logger.error(f"UDP error: {exc}")


# ---------------------------------------------------------------------------
# Main Collector
# ---------------------------------------------------------------------------

class SyslogCollector:
    """
    Production-grade async syslog collector.

    Data flow:
      UDP socket → deque (lock-free) → batch worker → parse → ClickHouse
    """

    def __init__(self, config: CollectorConfig = None):
        self.config = config or CollectorConfig()
        # Override from settings
        self.config.port = settings.syslog_port
        self.config.batch_size = settings.syslog_batch_size
        self.config.flush_interval = settings.syslog_flush_interval
        self.config.device_cache_ttl = max(settings.syslog_cache_ttl, 300)  # min 5 min
        self.config.worker_threads = settings.syslog_workers
        self.config.max_queue_size = settings.syslog_max_buffer
        self.config.metrics_interval = settings.syslog_metrics_interval

        # Core data structures
        self._raw_queue: deque = deque()  # (ip, raw_bytes) — lock-free in CPython
        self.device_cache = DeviceCache(ttl=self.config.device_cache_ttl)
        self.metrics = MetricsCollector()
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.worker_threads,
            thread_name_prefix='ch-insert',
        )

        # Reusable ClickHouse client (created once, reused for all inserts)
        self._ch_client = None

        self._running = False
        self._transport = None
        self._flush_task = None
        self._metrics_task = None
        self._ioc_refresh_task = None

        # Device stat accumulator (flushed periodically)
        self._device_stats: Dict[str, dict] = {}

    def _get_ch_client(self):
        """Get or create a reusable ClickHouse client."""
        if self._ch_client is None:
            self._ch_client = ClickHouseClient.get_client()
        return self._ch_client

    async def _process_batch(self):
        """
        Drain the raw queue, parse messages, and insert to ClickHouse.
        This is the main batch processing loop.
        """
        # Drain up to batch_size items from the deque
        batch_raw = []
        for _ in range(self.config.batch_size):
            try:
                item = self._raw_queue.popleft()
                batch_raw.append(item)
            except IndexError:
                break

        if not batch_raw:
            return

        # Group by device IP for efficient cache lookup
        now = datetime.now(timezone.utc)
        logs = []

        for client_ip, data in batch_raw:
            # Device lookup (cached for 5 min)
            cached = self.device_cache.get(client_ip)
            if cached is None:
                result = await get_or_create_device(client_ip)
                if result is None:
                    self.metrics.logs_dropped_device += 1
                    continue
                status, parser = result
                self.device_cache.set(client_ip, status, parser)
            else:
                status, parser = cached.status, cached.parser

            if status != DeviceStatus.APPROVED:
                self.metrics.logs_dropped_device += 1
                continue

            # Parse
            parsed = parse_syslog_message(data, parser)
            if parsed is None:
                self.metrics.logs_dropped_parse += 1
                continue

            (facility, severity, message, raw, srcip, dstip, srcport, dstport, proto,
             action, policyname, log_type, application, src_zone, dst_zone,
             session_end_reason, threat_id, vdom, parsed_data) = parsed

            logs.append((now, client_ip, facility, severity, message, raw,
                         srcip, dstip, srcport, dstport, proto, action, policyname,
                         log_type, application, src_zone, dst_zone, session_end_reason,
                         threat_id, vdom, parsed_data))

            # Accumulate device stats
            if client_ip not in self._device_stats:
                self._device_stats[client_ip] = {'count': 0, 'last_time': now}
            self._device_stats[client_ip]['count'] += 1
            self._device_stats[client_ip]['last_time'] = now
            self.metrics._by_device[client_ip] += 1

        if not logs:
            return

        # Run IOC matching on the batch (not per-packet)
        try:
            from .ioc_matcher import check_and_record_matches
            for log in logs:
                # log tuple: (now, ip, fac, sev, msg, raw, srcip, dstip, srcport, dstport, ...)
                check_and_record_matches(
                    srcip=log[6] or "",
                    dstip=log[7] or "",
                    log_timestamp=log[0],
                    device_ip=log[1],
                    srcport=log[8] or 0,
                    dstport=log[9] or 0,
                    action=log[11] or "",
                )
        except Exception:
            pass  # Never block the pipeline

        # Insert to ClickHouse in a thread (blocking I/O)
        loop = asyncio.get_event_loop()
        ch_client = self._get_ch_client()
        success, retries = await loop.run_in_executor(
            self.executor,
            flush_to_clickhouse,
            ch_client,
            logs,
            self.config.insert_retries,
            self.config.insert_retry_delay,
        )

        if success:
            self.metrics.logs_processed += len(logs)
            self.metrics.batches_flushed += 1
            self.metrics.insert_retries += retries
            if len(logs) >= 100:
                logger.info(f"Flushed {len(logs):,} logs (queue: {len(self._raw_queue):,})")
        else:
            self.metrics.flush_errors += 1
            # On total failure, try to recreate the client for next batch
            self._ch_client = None
            logger.error(f"LOST {len(logs):,} logs after {self.config.insert_retries} retries")

    async def _flush_loop(self):
        """Background loop: drain queue and flush to ClickHouse."""
        while self._running:
            try:
                queue_size = len(self._raw_queue)
                if queue_size > 0:
                    # Process multiple batches if queue is large
                    batches = max(1, queue_size // self.config.batch_size)
                    for _ in range(min(batches, 10)):  # cap at 10 batches per cycle
                        await self._process_batch()
                        if len(self._raw_queue) == 0:
                            break

                # Flush device stats periodically
                if self._device_stats:
                    stats_copy = self._device_stats.copy()
                    self._device_stats.clear()
                    asyncio.create_task(batch_update_device_stats(stats_copy))

            except Exception as e:
                logger.error(f"Flush loop error: {e}", exc_info=True)

            await asyncio.sleep(self.config.flush_interval)

    async def _metrics_loop(self):
        """Log performance metrics periodically."""
        while self._running:
            await asyncio.sleep(self.config.metrics_interval)
            report = self.metrics.get_report()
            cache_stats = self.device_cache.get_stats()

            logger.info(
                f"METRICS | "
                f"eps={report['eps']} | "
                f"received={report['logs_received']:,} | "
                f"processed={report['logs_processed']:,} | "
                f"dropped={report['total_dropped']:,} ({report['drop_pct']}) | "
                f"queue={len(self._raw_queue):,} | "
                f"devices={report['active_devices']} | "
                f"cache={cache_stats['hit_rate']} | "
                f"batches={report['batches_flushed']} | "
                f"retries={report['insert_retries']} | "
                f"errors={report['flush_errors']}"
            )

    async def _ioc_refresh_loop(self):
        """Refresh IOC matcher cache periodically."""
        while self._running:
            try:
                from .ioc_matcher import refresh_ioc_cache
                await refresh_ioc_cache()
            except Exception as e:
                logger.error(f"IOC cache refresh error: {e}")
            await asyncio.sleep(300)

    async def start(self):
        """Start the syslog collector."""
        self._running = True

        # Ensure ClickHouse table exists
        try:
            ClickHouseClient.ensure_table()
        except Exception as e:
            logger.error(f"ClickHouse setup failed: {e}")
            raise

        # Pre-warm ClickHouse client
        self._ch_client = ClickHouseClient.get_client()
        logger.info("ClickHouse client connected (reusable)")

        # Load IOC cache
        try:
            from .ioc_matcher import refresh_ioc_cache
            await refresh_ioc_cache()
            logger.info("IOC matcher cache loaded")
        except Exception as e:
            logger.warning(f"IOC cache initial load warning: {e}")

        # Pre-load all devices into cache
        try:
            async with _syslog_session_maker() as session:
                result = await session.execute(
                    text("SELECT ip_address::text, status, parser FROM devices_device")
                )
                rows = result.all()
                for row in rows:
                    self.device_cache.set(row.ip_address, row.status, row.parser)
                logger.info(f"Pre-loaded {len(rows)} devices into cache")
        except Exception as e:
            logger.warning(f"Device pre-load warning: {e}")

        # Create UDP endpoint
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self._raw_queue, self.config.max_queue_size, self.metrics),
            local_addr=(self.config.host, self.config.port),
        )
        self._transport = transport

        # Start background workers
        self._flush_task = asyncio.create_task(self._flush_loop())
        self._metrics_task = asyncio.create_task(self._metrics_loop())
        self._ioc_refresh_task = asyncio.create_task(self._ioc_refresh_loop())

        logger.info(f"Syslog collector started on {self.config.host}:{self.config.port}")
        logger.info(
            f"Config: batch_size={self.config.batch_size}, "
            f"flush_interval={self.config.flush_interval}s, "
            f"cache_ttl={self.config.device_cache_ttl}s, "
            f"max_queue={self.config.max_queue_size:,}, "
            f"workers={self.config.worker_threads}"
        )

    async def stop(self):
        """Graceful shutdown: flush all remaining logs."""
        logger.info("Stopping syslog collector...")
        self._running = False

        for task in (self._flush_task, self._metrics_task, self._ioc_refresh_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Final drain
        logger.info(f"Final drain: {len(self._raw_queue):,} packets in queue")
        while len(self._raw_queue) > 0:
            await self._process_batch()

        if self._transport:
            self._transport.close()

        self.executor.shutdown(wait=True)

        report = self.metrics.get_report()
        logger.info(
            f"FINAL | received={report['logs_received']:,} | "
            f"processed={report['logs_processed']:,} | "
            f"dropped={report['total_dropped']:,} ({report['drop_pct']})"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run_syslog_collector(
    batch_size: int = None,
    flush_interval: float = None,
    cache_ttl: int = None,
    workers: int = None,
):
    """Run the syslog collector as a standalone async service."""
    config = CollectorConfig()
    if batch_size:
        config.batch_size = batch_size
    if flush_interval:
        config.flush_interval = flush_interval
    if cache_ttl:
        config.device_cache_ttl = cache_ttl
    if workers:
        config.worker_threads = workers

    collector = SyslogCollector(config)

    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(collector.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    try:
        await collector.start()
        while collector._running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await collector.stop()
