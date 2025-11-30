#!/usr/bin/env python3
"""
NetLogs FastAPI Application Runner

Usage:
    python run_fastapi.py                    # Run with default settings
    python run_fastapi.py --port 8000        # Run on specific port
    python run_fastapi.py --reload           # Run with auto-reload (development)
    python run_fastapi.py --workers 4        # Run with multiple workers (production)
"""

import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description='Run NetLogs FastAPI Application')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload')
    parser.add_argument('--workers', type=int, default=1, help='Number of workers')
    parser.add_argument('--log-level', default='info', help='Log level')

    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║          NetLogs SOAR/SIEM Platform - FastAPI             ║
╠═══════════════════════════════════════════════════════════╣
║  Web UI:     http://{args.host}:{args.port}/                         ║
║  API Docs:   http://{args.host}:{args.port}/api/docs                 ║
║  Health:     http://{args.host}:{args.port}/api/health               ║
╚═══════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "fastapi_app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
        log_level=args.log_level,
    )


if __name__ == '__main__':
    main()
