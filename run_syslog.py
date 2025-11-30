#!/usr/bin/env python3
"""
Syslog Collector Runner

Runs the high-performance syslog collector as a standalone service.

Usage:
    python run_syslog.py
    python run_syslog.py --batch-size 10000

For production, run with root privileges for port 514:
    sudo python run_syslog.py
"""

import asyncio
import argparse
import logging
import sys

from fastapi_app.services.syslog_collector import run_syslog_collector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def main():
    parser = argparse.ArgumentParser(
        description='Run high-performance syslog collector'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=None,
        help='Logs per batch (default: 5000)'
    )
    parser.add_argument(
        '--flush-interval',
        type=float,
        default=None,
        help='Flush interval in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--cache-ttl',
        type=int,
        default=None,
        help='Device cache TTL in seconds (default: 60)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=None,
        help='Worker threads for DB operations (default: 4)'
    )

    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════════╗
║           NetLogs High-Performance Syslog Collector       ║
╠═══════════════════════════════════════════════════════════╣
║  Listening on UDP port 514                                ║
║  Press Ctrl+C to stop                                     ║
╚═══════════════════════════════════════════════════════════╝
    """)

    asyncio.run(run_syslog_collector(
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        cache_ttl=args.cache_ttl,
        workers=args.workers,
    ))


if __name__ == '__main__':
    main()
