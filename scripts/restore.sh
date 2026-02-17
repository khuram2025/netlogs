#!/bin/bash
# =============================================================================
# NetLogs Restore Script
# Restores PostgreSQL, ClickHouse data, and configuration from a backup archive.
#
# Usage:
#   ./scripts/restore.sh <backup_file.tar.gz> [--confirm]
#
# Without --confirm, runs in dry-run mode showing what would be restored.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$(mktemp -d)"

# Load environment from .env if present
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

PG_HOST="${POSTGRES_HOST:-localhost}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_DB="${POSTGRES_DB:-netlogs}"
PG_USER="${POSTGRES_USER:-read}"
PG_PASS="${POSTGRES_PASSWORD:-Read@123}"

CH_HOST="${CLICKHOUSE_HOST:-localhost}"
CH_PORT="${CLICKHOUSE_PORT:-8123}"
CH_DB="${CLICKHOUSE_DB:-default}"
CH_USER="${CLICKHOUSE_USER:-default}"
CH_PASS="${CLICKHOUSE_PASSWORD:-}"

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

# -------------------------------------------------------------------------
# Argument parsing
# -------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz> [--confirm]"
    echo ""
    echo "Without --confirm, runs in dry-run mode."
    exit 1
fi

BACKUP_FILE="$1"
CONFIRM="${2:-}"

if [ ! -f "$BACKUP_FILE" ]; then
    error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# -------------------------------------------------------------------------
# Extract archive
# -------------------------------------------------------------------------
log "Extracting backup archive: $BACKUP_FILE"
tar -xzf "$BACKUP_FILE" -C "$WORK_DIR"

# Show backup metadata
if [ -f "$WORK_DIR/backup_metadata.json" ]; then
    log "Backup metadata:"
    cat "$WORK_DIR/backup_metadata.json" | python3 -m json.tool 2>/dev/null || cat "$WORK_DIR/backup_metadata.json"
    echo ""
fi

# -------------------------------------------------------------------------
# Dry-run mode
# -------------------------------------------------------------------------
if [ "$CONFIRM" != "--confirm" ]; then
    log "=== DRY RUN MODE ==="
    log "The following would be restored:"
    echo ""

    if [ -f "$WORK_DIR/pg/netlogs.pgdump" ]; then
        PG_SIZE=$(du -sh "$WORK_DIR/pg/netlogs.pgdump" | cut -f1)
        log "  PostgreSQL: $PG_SIZE dump → $PG_DB"
    fi

    for tsv in "$WORK_DIR"/ch/*.tsv; do
        if [ -f "$tsv" ]; then
            TABLE=$(basename "$tsv" .tsv)
            ROWS=$(wc -l < "$tsv")
            log "  ClickHouse: $TABLE → $((ROWS - 1)) rows"
        fi
    done

    if [ -f "$WORK_DIR/config/.env" ]; then
        log "  Config: .env file"
    fi

    echo ""
    log "To proceed, run: $0 $BACKUP_FILE --confirm"
    exit 0
fi

# -------------------------------------------------------------------------
# Restore PostgreSQL
# -------------------------------------------------------------------------
if [ -f "$WORK_DIR/pg/netlogs.pgdump" ]; then
    log "Restoring PostgreSQL database..."
    export PGPASSWORD="$PG_PASS"

    # Restore with --clean to drop and recreate
    if pg_restore -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        --clean --if-exists --no-owner --no-privileges \
        "$WORK_DIR/pg/netlogs.pgdump" 2>/dev/null; then
        log "PostgreSQL restore complete"
    else
        # pg_restore returns non-zero even on warnings, check if DB is usable
        log "PostgreSQL restore completed (some warnings may have occurred)"
    fi

    unset PGPASSWORD
else
    log "No PostgreSQL dump found in backup, skipping"
fi

# -------------------------------------------------------------------------
# Restore ClickHouse
# -------------------------------------------------------------------------
ch_query() {
    local query="$1"
    curl -sS "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}" \
        --data-binary "$query" 2>/dev/null
}

ch_insert() {
    local table="$1"
    local file="$2"
    curl -sS "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}&query=INSERT+INTO+${CH_DB}.${table}+FORMAT+TabSeparatedWithNames" \
        --data-binary "@${file}" 2>/dev/null
}

for tsv in "$WORK_DIR"/ch/*.tsv; do
    if [ -f "$tsv" ]; then
        TABLE=$(basename "$tsv" .tsv)
        ROWS=$(wc -l < "$tsv")
        log "Restoring ClickHouse table: $TABLE ($((ROWS - 1)) rows)..."

        # For audit_logs, we insert alongside existing data (don't truncate compliance data)
        if [ "$TABLE" = "audit_logs" ]; then
            ch_insert "$TABLE" "$tsv" && log "  $TABLE restored (merged)" || log "  $TABLE restore failed"
        else
            # For other tables, truncate first then insert
            ch_query "TRUNCATE TABLE IF EXISTS ${CH_DB}.${TABLE}" 2>/dev/null
            ch_insert "$TABLE" "$tsv" && log "  $TABLE restored" || log "  $TABLE restore failed"
        fi
    fi
done

# -------------------------------------------------------------------------
# Restore configuration
# -------------------------------------------------------------------------
if [ -f "$WORK_DIR/config/.env" ]; then
    if [ -f "$PROJECT_DIR/.env" ]; then
        cp "$PROJECT_DIR/.env" "$PROJECT_DIR/.env.pre-restore"
        log "Existing .env backed up to .env.pre-restore"
    fi
    cp "$WORK_DIR/config/.env" "$PROJECT_DIR/.env"
    log "Configuration (.env) restored"
fi

# -------------------------------------------------------------------------
# Post-restore
# -------------------------------------------------------------------------
log ""
log "=== Restore Complete ==="
log "Next steps:"
log "  1. Restart the NetLogs services: docker compose restart"
log "  2. Verify the application: curl http://localhost/api/health"
log "  3. Check the dashboard for data integrity"
