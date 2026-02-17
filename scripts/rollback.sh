#!/bin/bash
# =============================================================================
# NetLogs Rollback Script
# Restores from the most recent backup and restarts services.
#
# Usage:
#   ./scripts/rollback.sh [backup_file.tar.gz]
#
# Without arguments, uses the most recent backup.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Load environment
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "[$(date '+%H:%M:%S')] ${GREEN}$1${NC}"; }
warn()  { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}WARNING: $1${NC}"; }
error() { echo -e "[$(date '+%H:%M:%S')] ${RED}ERROR: $1${NC}" >&2; }

BACKUP_DIR="${BACKUP_PATH:-$PROJECT_DIR/backups}"

# Find backup file
if [ $# -ge 1 ]; then
    BACKUP_FILE="$1"
else
    BACKUP_FILE=$(ls -t "$BACKUP_DIR"/netlogs-backup-*.tar.gz 2>/dev/null | head -1)
    if [ -z "$BACKUP_FILE" ]; then
        error "No backup files found in $BACKUP_DIR"
        exit 1
    fi
fi

if [ ! -f "$BACKUP_FILE" ]; then
    error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "==========================================="
echo "   NetLogs Rollback"
echo "   Backup: $(basename "$BACKUP_FILE")"
echo "==========================================="
echo ""

# Confirm
read -p "This will restore from backup and restart all services. Continue? [y/N] " CONFIRM
if [ "${CONFIRM,,}" != "y" ]; then
    echo "Aborted."
    exit 0
fi

# -------------------------------------------------------------------------
# Step 1: Stop application services (keep databases running)
# -------------------------------------------------------------------------
log "Step 1: Stopping application services..."
docker compose stop web syslog nginx 2>/dev/null || true
log "  Services stopped"

echo ""

# -------------------------------------------------------------------------
# Step 2: Restore from backup
# -------------------------------------------------------------------------
log "Step 2: Restoring from backup..."
if "$SCRIPT_DIR/restore.sh" "$BACKUP_FILE" --confirm; then
    log "  Restore complete"
else
    error "Restore failed"
    log "Restarting services with current data..."
    docker compose up -d web syslog nginx
    exit 1
fi

echo ""

# -------------------------------------------------------------------------
# Step 3: Restart all services
# -------------------------------------------------------------------------
log "Step 3: Restarting services..."
docker compose up -d
sleep 10

# Wait for health
MAX_WAIT=60
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    if docker compose exec -T web curl -sf http://127.0.0.1:8000/api/health/simple >/dev/null 2>&1; then
        log "  Services healthy"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done

echo ""

# -------------------------------------------------------------------------
# Step 4: Verify
# -------------------------------------------------------------------------
log "Step 4: Verification..."
docker compose ps --format "table {{.Service}}\t{{.Status}}" 2>/dev/null || docker compose ps

echo ""
echo "==========================================="
echo -e "   ${GREEN}Rollback complete!${NC}"
echo "   Restored from: $(basename "$BACKUP_FILE")"
echo "==========================================="
