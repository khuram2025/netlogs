#!/usr/bin/env python3
"""
Log Cleanup Script

Deletes old logs from ClickHouse based on per-device retention policies.

Usage:
    python cleanup_logs.py                    # Dry run
    python cleanup_logs.py --execute          # Actually delete
    python cleanup_logs.py --device 10.0.0.1  # Specific device

Recommended cron job:
    0 2 * * * cd /home/net/zentryc && /path/to/venv/bin/python cleanup_logs.py --execute >> logs/cleanup.log 2>&1
"""

import asyncio
import sys
sys.path.insert(0, '/home/net/zentryc')

from fastapi_app.cli.cleanup_logs import main

if __name__ == '__main__':
    main()
