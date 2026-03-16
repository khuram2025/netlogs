#!/bin/bash
# =============================================================================
# Zentryc Backup Script
# Creates a compressed backup archive of PostgreSQL, ClickHouse, and config.
#
# Usage:
#   ./scripts/backup.sh [backup_dir]
#
# Default backup directory: ./backups/
# Output: zentryc-backup-YYYYMMDD-HHMMSS.tar.gz
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${1:-${BACKUP_PATH:-$PROJECT_DIR/backups}}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
WORK_DIR="$(mktemp -d)"
ARCHIVE_NAME="zentryc-backup-${TIMESTAMP}.tar.gz"

# Load environment from .env if present
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Database defaults (can be overridden by env)
PG_HOST="${POSTGRES_HOST:-localhost}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_DB="${POSTGRES_DB:-zentryc}"
PG_USER="${POSTGRES_USER:-read}"
PG_PASS="${POSTGRES_PASSWORD:-Read@123}"

CH_HOST="${CLICKHOUSE_HOST:-localhost}"
CH_PORT="${CLICKHOUSE_PORT:-8123}"
CH_DB="${CLICKHOUSE_DB:-default}"
CH_USER="${CLICKHOUSE_USER:-default}"
CH_PASS="${CLICKHOUSE_PASSWORD:-}"

# Cleanup on exit
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

# Create backup directory
mkdir -p "$BACKUP_DIR"
mkdir -p "$WORK_DIR/pg" "$WORK_DIR/ch" "$WORK_DIR/config"

log "Starting Zentryc backup..."
log "Backup directory: $BACKUP_DIR"
log "Working directory: $WORK_DIR"

# -------------------------------------------------------------------------
# 1. PostgreSQL backup
# -------------------------------------------------------------------------
log "Backing up PostgreSQL ($PG_HOST:$PG_PORT/$PG_DB)..."
export PGPASSWORD="$PG_PASS"

if pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
    --format=custom --no-owner --no-privileges \
    -f "$WORK_DIR/pg/zentryc.pgdump" 2>/dev/null; then
    PG_SIZE=$(du -sh "$WORK_DIR/pg/zentryc.pgdump" | cut -f1)
    log "PostgreSQL backup complete ($PG_SIZE)"
else
    error "PostgreSQL backup failed"
    exit 1
fi

unset PGPASSWORD

# -------------------------------------------------------------------------
# 2. ClickHouse backup (export key tables as TSV)
# -------------------------------------------------------------------------
log "Backing up ClickHouse ($CH_HOST:$CH_PORT)..."

ch_query() {
    local query="$1"
    local output="$2"
    local auth=""
    if [ -n "$CH_PASS" ]; then
        auth="--user $CH_USER --password $CH_PASS"
    fi
    curl -sS "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}" \
        --data-binary "$query" > "$output" 2>/dev/null
}

# Export audit_logs (important for compliance)
log "  Exporting audit_logs..."
if ch_query "SELECT * FROM ${CH_DB}.audit_logs FORMAT TabSeparatedWithNames" \
    "$WORK_DIR/ch/audit_logs.tsv"; then
    AUDIT_LINES=$(wc -l < "$WORK_DIR/ch/audit_logs.tsv")
    log "  audit_logs: $((AUDIT_LINES - 1)) rows"
else
    log "  audit_logs: export failed (table may not exist)"
fi

# Export syslogs metadata (last 24h only for manageability — full backup uses ClickHouse native)
log "  Exporting recent syslogs (last 24h)..."
if ch_query "SELECT * FROM ${CH_DB}.syslogs WHERE timestamp >= now() - INTERVAL 1 DAY FORMAT TabSeparatedWithNames" \
    "$WORK_DIR/ch/syslogs_recent.tsv"; then
    SYSLOG_LINES=$(wc -l < "$WORK_DIR/ch/syslogs_recent.tsv")
    log "  syslogs (24h): $((SYSLOG_LINES - 1)) rows"
else
    log "  syslogs: export failed"
fi

# Export IOC matches
log "  Exporting ioc_matches..."
if ch_query "SELECT * FROM ${CH_DB}.ioc_matches FORMAT TabSeparatedWithNames" \
    "$WORK_DIR/ch/ioc_matches.tsv" 2>/dev/null; then
    IOC_LINES=$(wc -l < "$WORK_DIR/ch/ioc_matches.tsv")
    log "  ioc_matches: $((IOC_LINES - 1)) rows"
else
    log "  ioc_matches: export failed (table may not exist)"
fi

# Export correlation matches
log "  Exporting correlation_matches..."
if ch_query "SELECT * FROM ${CH_DB}.correlation_matches FORMAT TabSeparatedWithNames" \
    "$WORK_DIR/ch/correlation_matches.tsv" 2>/dev/null; then
    CORR_LINES=$(wc -l < "$WORK_DIR/ch/correlation_matches.tsv")
    log "  correlation_matches: $((CORR_LINES - 1)) rows"
else
    log "  correlation_matches: export failed (table may not exist)"
fi

# -------------------------------------------------------------------------
# 3. Configuration backup
# -------------------------------------------------------------------------
log "Backing up configuration..."

# .env file (if exists)
[ -f "$PROJECT_DIR/.env" ] && cp "$PROJECT_DIR/.env" "$WORK_DIR/config/.env"

# Alembic version
if [ -f "$PROJECT_DIR/alembic.ini" ]; then
    cp "$PROJECT_DIR/alembic.ini" "$WORK_DIR/config/"
fi

# Version info
if [ -f "$PROJECT_DIR/fastapi_app/__version__.py" ]; then
    cp "$PROJECT_DIR/fastapi_app/__version__.py" "$WORK_DIR/config/"
fi

# Save metadata
cat > "$WORK_DIR/backup_metadata.json" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "version": "$(grep '__version__' "$PROJECT_DIR/fastapi_app/__version__.py" 2>/dev/null | cut -d'"' -f2 || echo 'unknown')",
    "pg_host": "$PG_HOST",
    "pg_db": "$PG_DB",
    "ch_host": "$CH_HOST",
    "backup_type": "full"
}
EOF

log "Configuration backup complete"

# -------------------------------------------------------------------------
# 4. Create compressed archive
# -------------------------------------------------------------------------
log "Creating archive: $ARCHIVE_NAME"

tar -czf "$BACKUP_DIR/$ARCHIVE_NAME" -C "$WORK_DIR" .

ARCHIVE_SIZE=$(du -sh "$BACKUP_DIR/$ARCHIVE_NAME" | cut -f1)
log "Backup complete: $BACKUP_DIR/$ARCHIVE_NAME ($ARCHIVE_SIZE)"

# -------------------------------------------------------------------------
# 5. Retention cleanup (keep last N backups)
# -------------------------------------------------------------------------
RETENTION_COUNT="${BACKUP_RETENTION_COUNT:-30}"
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "zentryc-backup-*.tar.gz" -type f | wc -l)

if [ "$BACKUP_COUNT" -gt "$RETENTION_COUNT" ]; then
    EXCESS=$((BACKUP_COUNT - RETENTION_COUNT))
    log "Cleaning up $EXCESS old backup(s) (keeping $RETENTION_COUNT)..."
    find "$BACKUP_DIR" -name "zentryc-backup-*.tar.gz" -type f -printf '%T+ %p\n' \
        | sort | head -n "$EXCESS" | cut -d' ' -f2- \
        | xargs rm -f
fi

# Output result for programmatic use
echo "$BACKUP_DIR/$ARCHIVE_NAME"
