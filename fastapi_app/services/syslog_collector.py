"""
High-Performance Syslog Collector for Enterprise Firewall Log Management

Migrated from Django to FastAPI with full async support.

Architecture:
- Asyncio-based UDP receiver for non-blocking I/O
- Multi-worker processing with configurable parallelism
- In-memory device cache with TTL to minimize DB queries
- Large batch inserts to ClickHouse (optimized for throughput)
- Async PostgreSQL connection pooling
- Graceful shutdown with buffer flushing
- Comprehensive logging and metrics

Performance Targets:
- 100,000+ logs/minute sustained throughput
- <10ms average processing latency
- <1% CPU usage per 10k logs/minute
"""

import asyncio
import signal
import time
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
from threading import Lock

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import settings
from ..db.database import async_session_maker
from ..db.clickhouse import ClickHouseClient
from ..models.device import Device, DeviceStatus
from .parsers import get_parser

logger = logging.getLogger('syslog_collector')


@dataclass
class CollectorConfig:
    """Syslog collector configuration."""
    host: str = "0.0.0.0"
    port: int = 514
    batch_size: int = 5000
    flush_interval: float = 2.0
    device_cache_ttl: int = 60
    worker_threads: int = 4
    max_buffer_size: int = 100000
    metrics_interval: int = 30


@dataclass
class CachedDevice:
    """Cached device information."""
    status: str
    parser: str
    cached_at: float

    def is_expired(self, ttl: int) -> bool:
        return (time.time() - self.cached_at) > ttl


class DeviceCache:
    """Thread-safe device cache with TTL."""

    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self._cache: Dict[str, CachedDevice] = {}
        self._lock = Lock()
        self._stats = {'hits': 0, 'misses': 0}

    def get(self, ip: str) -> Optional[CachedDevice]:
        """Get device from cache, returns None if expired or not found."""
        with self._lock:
            cached = self._cache.get(ip)
            if cached and not cached.is_expired(self.ttl):
                self._stats['hits'] += 1
                return cached
            self._stats['misses'] += 1
            return None

    def set(self, ip: str, status: str, parser: str):
        """Cache device info."""
        with self._lock:
            self._cache[ip] = CachedDevice(
                status=status,
                parser=parser,
                cached_at=time.time()
            )

    def invalidate(self, ip: str):
        """Remove device from cache."""
        with self._lock:
            self._cache.pop(ip, None)

    def clear(self):
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            total = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total * 100) if total > 0 else 0
            return {
                'size': len(self._cache),
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_rate': f"{hit_rate:.1f}%"
            }


class MetricsCollector:
    """Collect and report performance metrics."""

    def __init__(self):
        self._lock = Lock()
        self.reset()

    def reset(self):
        """Reset all metrics."""
        with self._lock:
            self._logs_received = 0
            self._logs_processed = 0
            self._logs_dropped = 0
            self._batches_flushed = 0
            self._flush_errors = 0
            self._start_time = time.time()
            self._logs_by_device: Dict[str, int] = defaultdict(int)

    def log_received(self, ip: str):
        with self._lock:
            self._logs_received += 1
            self._logs_by_device[ip] += 1

    def log_processed(self):
        with self._lock:
            self._logs_processed += 1

    def log_dropped(self):
        with self._lock:
            self._logs_dropped += 1

    def batch_flushed(self, count: int):
        with self._lock:
            self._batches_flushed += 1

    def flush_error(self):
        with self._lock:
            self._flush_errors += 1

    def get_report(self) -> dict:
        with self._lock:
            elapsed = time.time() - self._start_time
            rate = self._logs_received / elapsed if elapsed > 0 else 0
            return {
                'elapsed_seconds': int(elapsed),
                'logs_received': self._logs_received,
                'logs_processed': self._logs_processed,
                'logs_dropped': self._logs_dropped,
                'logs_per_second': int(rate),
                'batches_flushed': self._batches_flushed,
                'flush_errors': self._flush_errors,
                'active_devices': len(self._logs_by_device),
                'top_devices': dict(sorted(
                    self._logs_by_device.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5])
            }


class LogBuffer:
    """Thread-safe bounded log buffer with batch extraction."""

    def __init__(self, max_size: int = 100000):
        self.max_size = max_size
        self._buffer: List[tuple] = []
        self._lock = Lock()
        self._device_updates: Dict[str, dict] = {}

    def add(self, log_entry: tuple, device_ip: str, timestamp) -> bool:
        """Add log to buffer. Returns False if buffer full."""
        with self._lock:
            if len(self._buffer) >= self.max_size:
                return False
            self._buffer.append(log_entry)

            if device_ip not in self._device_updates:
                self._device_updates[device_ip] = {'count': 0, 'last_time': timestamp}
            self._device_updates[device_ip]['count'] += 1
            self._device_updates[device_ip]['last_time'] = timestamp
            return True

    def extract_batch(self, batch_size: int) -> Tuple[List[tuple], Dict[str, dict]]:
        """Extract a batch of logs and device updates atomically."""
        with self._lock:
            if not self._buffer:
                return [], {}

            batch = self._buffer[:batch_size]
            self._buffer = self._buffer[batch_size:]
            updates = self._device_updates.copy()
            self._device_updates.clear()

            return batch, updates

    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    def flush_all(self) -> Tuple[List[tuple], Dict[str, dict]]:
        """Flush entire buffer."""
        with self._lock:
            batch = self._buffer[:]
            self._buffer = []
            updates = self._device_updates.copy()
            self._device_updates.clear()
            return batch, updates


# Pre-compiled regex for performance
PRI_REGEX = re.compile(r'^<(\d{1,3})>(.*)', re.DOTALL)


def parse_syslog_message(data: bytes, device_parser: str) -> Optional[tuple]:
    """
    Parse raw syslog message.
    Returns: (facility, severity, message, raw, srcip, dstip, srcport, dstport, proto, action, parsed_data) or None on error
    """
    try:
        decoded = data.decode('utf-8', errors='replace')

        facility = 1  # user
        severity = 6  # info
        message = decoded

        match = PRI_REGEX.match(decoded)
        if match:
            pri = int(match.group(1))
            facility = pri >> 3
            severity = pri & 7
            message = match.group(2).strip()

        parser = get_parser(device_parser)
        parsed_data = parser.parse(message)

        # Extract key fields for dedicated columns (support both Fortinet and Palo Alto field names)
        srcip = parsed_data.get('srcip') or parsed_data.get('src_ip', '')
        dstip = parsed_data.get('dstip') or parsed_data.get('dst_ip', '')
        action = parsed_data.get('action', '')

        # Parse ports as integers (default to 0)
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

        # Parse protocol as integer (default to 0)
        proto_str = parsed_data.get('proto') or parsed_data.get('protocol', '0')
        try:
            proto = int(proto_str) if proto_str else 0
        except (ValueError, TypeError):
            proto = 0

        return (facility, severity, message, decoded, srcip, dstip, srcport, dstport, proto, action, parsed_data)
    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None


async def get_or_create_device(ip: str) -> Optional[Tuple[str, str]]:
    """
    Get device status and parser from database.
    Creates new device as PENDING if not exists.
    Returns: (status, parser) or None on error
    """
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(Device).where(Device.ip_address == ip)
            )
            device = result.scalar_one_or_none()

            if device is None:
                device = Device(
                    ip_address=ip,
                    status=DeviceStatus.PENDING
                )
                session.add(device)
                await session.commit()
                logger.info(f"New device detected: {ip}")
                return (device.status, device.parser)

            return (device.status, device.parser)
    except Exception as e:
        logger.error(f"Database error for {ip}: {e}")
        return None


async def update_device_stats(updates: Dict[str, dict]):
    """Batch update device statistics."""
    if not updates:
        return

    try:
        async with async_session_maker() as session:
            for ip, data in updates.items():
                await session.execute(
                    update(Device)
                    .where(Device.ip_address == ip)
                    .values(
                        last_log_received=data['last_time'],
                        log_count=Device.log_count + data['count']
                    )
                )
            await session.commit()
    except Exception as e:
        logger.error(f"Failed to update device stats: {e}")


def flush_to_clickhouse(logs: List[tuple]) -> bool:
    """Insert logs to ClickHouse. Returns success status."""
    if not logs:
        return True
    try:
        ClickHouseClient.insert_logs(logs)
        return True
    except Exception as e:
        logger.error(f"ClickHouse insert failed: {e}")
        return False


class SyslogProtocol(asyncio.DatagramProtocol):
    """High-performance async UDP protocol handler."""

    def __init__(self, collector: 'SyslogCollector'):
        self.collector = collector
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("UDP transport ready")

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming UDP datagram."""
        client_ip = addr[0]
        asyncio.create_task(self.collector.process_log(client_ip, data))

    def error_received(self, exc):
        logger.error(f"UDP error: {exc}")


class SyslogCollector:
    """
    High-performance async syslog collector.

    Features:
    - Async UDP receiver
    - Device caching with TTL
    - Batched ClickHouse inserts
    - Background device stat updates
    - Graceful shutdown
    """

    def __init__(self, config: CollectorConfig = None):
        self.config = config or CollectorConfig()
        self.config.port = settings.syslog_port
        self.config.batch_size = settings.syslog_batch_size
        self.config.flush_interval = settings.syslog_flush_interval
        self.config.device_cache_ttl = settings.syslog_cache_ttl
        self.config.worker_threads = settings.syslog_workers
        self.config.max_buffer_size = settings.syslog_max_buffer
        self.config.metrics_interval = settings.syslog_metrics_interval

        self.device_cache = DeviceCache(ttl=self.config.device_cache_ttl)
        self.log_buffer = LogBuffer(max_size=self.config.max_buffer_size)
        self.metrics = MetricsCollector()
        self.executor = ThreadPoolExecutor(max_workers=self.config.worker_threads)

        self._running = False
        self._loop = None
        self._transport = None
        self._flush_task = None
        self._metrics_task = None

    async def process_log(self, client_ip: str, data: bytes):
        """Process incoming log (called from protocol handler)."""
        self.metrics.log_received(client_ip)

        cached = self.device_cache.get(client_ip)

        if cached is None:
            result = await get_or_create_device(client_ip)
            if result is None:
                self.metrics.log_dropped()
                return
            status, parser = result
            self.device_cache.set(client_ip, status, parser)
        else:
            status, parser = cached.status, cached.parser

        if status != DeviceStatus.APPROVED:
            self.metrics.log_dropped()
            return

        parsed = parse_syslog_message(data, parser)
        if parsed is None:
            self.metrics.log_dropped()
            return

        facility, severity, message, raw, srcip, dstip, srcport, dstport, proto, action, parsed_data = parsed
        now = datetime.now(timezone.utc)

        # Log entry now includes dedicated columns for key fields
        log_entry = (now, client_ip, facility, severity, message, raw,
                     srcip, dstip, srcport, dstport, proto, action, parsed_data)

        if not self.log_buffer.add(log_entry, client_ip, now):
            logger.warning("Buffer full! Dropping log")
            self.metrics.log_dropped()
            return

        self.metrics.log_processed()

    async def _flush_loop(self):
        """Background task to flush logs periodically."""
        while self._running:
            await asyncio.sleep(self.config.flush_interval)
            await self._flush_batch()

    async def _flush_batch(self):
        """Flush a batch of logs to ClickHouse."""
        buffer_size = self.log_buffer.size()
        if buffer_size == 0:
            return

        logs, device_updates = self.log_buffer.extract_batch(self.config.batch_size)
        if not logs:
            return

        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(
            self.executor,
            flush_to_clickhouse,
            logs
        )

        if success:
            self.metrics.batch_flushed(len(logs))
            logger.info(f"Flushed {len(logs)} logs to ClickHouse (buffer: {self.log_buffer.size()})")
            asyncio.create_task(update_device_stats(device_updates))
        else:
            self.metrics.flush_error()

    async def _metrics_loop(self):
        """Background task to log metrics periodically."""
        while self._running:
            await asyncio.sleep(self.config.metrics_interval)
            report = self.metrics.get_report()
            cache_stats = self.device_cache.get_stats()

            logger.info(
                f"METRICS | "
                f"rate={report['logs_per_second']}/s | "
                f"received={report['logs_received']} | "
                f"processed={report['logs_processed']} | "
                f"dropped={report['logs_dropped']} | "
                f"buffer={self.log_buffer.size()} | "
                f"devices={report['active_devices']} | "
                f"cache_hit={cache_stats['hit_rate']}"
            )

    async def start(self):
        """Start the syslog collector."""
        self._running = True
        self._loop = asyncio.get_event_loop()

        try:
            ClickHouseClient.ensure_table()
        except Exception as e:
            logger.error(f"ClickHouse setup failed: {e}")
            raise

        transport, protocol = await self._loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self),
            local_addr=(self.config.host, self.config.port)
        )
        self._transport = transport

        self._flush_task = asyncio.create_task(self._flush_loop())
        self._metrics_task = asyncio.create_task(self._metrics_loop())

        logger.info(f"Syslog collector started on {self.config.host}:{self.config.port}")
        logger.info(f"Config: batch_size={self.config.batch_size}, flush_interval={self.config.flush_interval}s, cache_ttl={self.config.device_cache_ttl}s")

    async def stop(self):
        """Stop the collector gracefully."""
        logger.info("Stopping syslog collector...")
        self._running = False

        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        if self._metrics_task:
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass

        logger.info("Flushing remaining logs...")
        remaining_logs, device_updates = self.log_buffer.flush_all()
        if remaining_logs:
            flush_to_clickhouse(remaining_logs)
            await update_device_stats(device_updates)
            logger.info(f"Final flush: {len(remaining_logs)} logs")

        if self._transport:
            self._transport.close()

        self.executor.shutdown(wait=True)

        report = self.metrics.get_report()
        logger.info(f"FINAL STATS: received={report['logs_received']}, processed={report['logs_processed']}, dropped={report['logs_dropped']}")


async def run_syslog_collector(
    batch_size: int = None,
    flush_interval: float = None,
    cache_ttl: int = None,
    workers: int = None
):
    """Run the syslog collector as a standalone service."""
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


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    asyncio.run(run_syslog_collector())
