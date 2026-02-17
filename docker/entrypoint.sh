#!/bin/bash
set -e

MODE="${1:-web}"

echo "============================================"
echo " NetLogs SOAR/SIEM Platform"
echo " Mode: ${MODE}"
echo "============================================"

# ---------------------------------------------------------------------------
# Auto-generate SECRET_KEY if not set
# ---------------------------------------------------------------------------
if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "change-me-in-production" ]; then
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    echo "[entrypoint] Auto-generated SECRET_KEY (set SECRET_KEY env var for persistence)"
fi

# ---------------------------------------------------------------------------
# Wait for PostgreSQL
# ---------------------------------------------------------------------------
PGHOST="${POSTGRES_HOST:-postgres}"
PGPORT="${POSTGRES_PORT:-5432}"
echo "[entrypoint] Waiting for PostgreSQL at ${PGHOST}:${PGPORT}..."

SECONDS_WAITED=0
TIMEOUT=60
until python3 -c "
import socket, sys
try:
    s = socket.create_connection(('${PGHOST}', ${PGPORT}), timeout=2)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    SECONDS_WAITED=$((SECONDS_WAITED + 1))
    if [ "$SECONDS_WAITED" -ge "$TIMEOUT" ]; then
        echo "[entrypoint] ERROR: PostgreSQL not ready after ${TIMEOUT}s - aborting"
        exit 1
    fi
    sleep 1
done
echo "[entrypoint] PostgreSQL is ready"

# ---------------------------------------------------------------------------
# Wait for ClickHouse
# ---------------------------------------------------------------------------
CHHOST="${CLICKHOUSE_HOST:-clickhouse}"
CHPORT="${CLICKHOUSE_PORT:-8123}"
echo "[entrypoint] Waiting for ClickHouse at ${CHHOST}:${CHPORT}..."

SECONDS_WAITED=0
until python3 -c "
import socket, sys
try:
    s = socket.create_connection(('${CHHOST}', ${CHPORT}), timeout=2)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    SECONDS_WAITED=$((SECONDS_WAITED + 1))
    if [ "$SECONDS_WAITED" -ge "$TIMEOUT" ]; then
        echo "[entrypoint] ERROR: ClickHouse not ready after ${TIMEOUT}s - aborting"
        exit 1
    fi
    sleep 1
done
echo "[entrypoint] ClickHouse is ready"

# ---------------------------------------------------------------------------
# Launch the appropriate process
# ---------------------------------------------------------------------------
case "$MODE" in
    web)
        WORKERS="${WORKERS:-4}"
        echo "[entrypoint] Starting web server with ${WORKERS} workers..."
        exec python run_fastapi.py --host 0.0.0.0 --port 8000 --workers "$WORKERS"
        ;;
    syslog)
        echo "[entrypoint] Starting syslog collector..."
        exec python run_syslog.py
        ;;
    *)
        echo "[entrypoint] ERROR: Unknown mode '${MODE}'. Use 'web' or 'syslog'."
        exit 1
        ;;
esac
