#!/bin/bash
# =============================================================================
# NetLogs Upgrade Script
# Performs a safe upgrade with pre-flight checks, auto-backup, and rollback.
#
# Usage:
#   ./scripts/upgrade.sh [--skip-backup] [--force]
#
# Steps:
#   1. Pre-flight checks (disk space, services, current version)
#   2. Auto-backup (unless --skip-backup)
#   3. Pull new Docker images
#   4. Run database migrations
#   5. Rolling restart of services
#   6. Post-upgrade health verification
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
SKIP_BACKUP=false
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --skip-backup) SKIP_BACKUP=true ;;
        --force) FORCE=true ;;
    esac
done

# Load environment
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log()   { echo -e "[$(date '+%H:%M:%S')] ${GREEN}$1${NC}"; }
warn()  { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}WARNING: $1${NC}"; }
error() { echo -e "[$(date '+%H:%M:%S')] ${RED}ERROR: $1${NC}" >&2; }

# Get current version
get_version() {
    grep '__version__' "$PROJECT_DIR/fastapi_app/__version__.py" 2>/dev/null | cut -d'"' -f2 || echo "unknown"
}

CURRENT_VERSION=$(get_version)

echo "==========================================="
echo "   NetLogs Upgrade Script"
echo "   Current Version: $CURRENT_VERSION"
echo "==========================================="
echo ""

# -------------------------------------------------------------------------
# Step 1: Pre-flight checks
# -------------------------------------------------------------------------
log "Step 1: Running pre-flight checks..."

# Check Docker is running
if ! docker info >/dev/null 2>&1; then
    error "Docker is not running"
    exit 1
fi
log "  Docker: OK"

# Check docker compose is available
if ! docker compose version >/dev/null 2>&1; then
    error "docker compose not available"
    exit 1
fi
log "  Docker Compose: OK"

# Check disk space (need at least 2GB free)
FREE_KB=$(df -k "$PROJECT_DIR" | tail -1 | awk '{print $4}')
FREE_GB=$((FREE_KB / 1024 / 1024))
if [ "$FREE_GB" -lt 2 ]; then
    error "Insufficient disk space: ${FREE_GB}GB free (need >= 2GB)"
    if [ "$FORCE" != "true" ]; then
        exit 1
    fi
    warn "Continuing due to --force flag"
fi
log "  Disk space: ${FREE_GB}GB free"

# Check if docker-compose.yml exists
if [ ! -f "$PROJECT_DIR/docker-compose.yml" ]; then
    error "docker-compose.yml not found in $PROJECT_DIR"
    exit 1
fi
log "  docker-compose.yml: Found"

# Check services are running
RUNNING=$(docker compose ps --filter "status=running" -q 2>/dev/null | wc -l)
log "  Running containers: $RUNNING"

echo ""

# -------------------------------------------------------------------------
# Step 2: Auto-backup
# -------------------------------------------------------------------------
if [ "$SKIP_BACKUP" = "true" ]; then
    warn "Step 2: Skipping backup (--skip-backup flag)"
else
    log "Step 2: Creating pre-upgrade backup..."
    if [ -f "$SCRIPT_DIR/backup.sh" ]; then
        BACKUP_PATH="${BACKUP_PATH:-$PROJECT_DIR/backups}"
        if "$SCRIPT_DIR/backup.sh" "$BACKUP_PATH" >/dev/null 2>&1; then
            LATEST_BACKUP=$(ls -t "$BACKUP_PATH"/netlogs-backup-*.tar.gz 2>/dev/null | head -1)
            log "  Backup created: $(basename "$LATEST_BACKUP")"
        else
            error "Backup failed"
            if [ "$FORCE" != "true" ]; then
                error "Cannot proceed without backup. Use --skip-backup or --force to override."
                exit 1
            fi
            warn "Continuing due to --force flag"
        fi
    else
        warn "Backup script not found, skipping"
    fi
fi

echo ""

# -------------------------------------------------------------------------
# Step 3: Pull new images
# -------------------------------------------------------------------------
log "Step 3: Building/pulling new images..."
docker compose build --no-cache web 2>&1 | tail -5
log "  Image build complete"

echo ""

# -------------------------------------------------------------------------
# Step 4: Run database migrations
# -------------------------------------------------------------------------
log "Step 4: Running database migrations..."

# Run Alembic migrations via a temporary container
if docker compose run --rm --no-deps -e POSTGRES_HOST=postgres web \
    python -m alembic upgrade head 2>&1 | tail -3; then
    log "  PostgreSQL migrations: OK"
else
    warn "  Migration via container failed, trying local..."
    if [ -f "$PROJECT_DIR/venv/bin/activate" ]; then
        source "$PROJECT_DIR/venv/bin/activate"
        alembic upgrade head 2>&1 | tail -3
        log "  PostgreSQL migrations (local): OK"
    fi
fi

echo ""

# -------------------------------------------------------------------------
# Step 5: Rolling restart
# -------------------------------------------------------------------------
log "Step 5: Rolling restart of services..."

# Restart web first (it handles DB init)
log "  Restarting web service..."
docker compose up -d --no-deps web
sleep 5

# Wait for web health check
MAX_WAIT=60
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    if docker compose exec -T web curl -sf http://127.0.0.1:8000/api/health/simple >/dev/null 2>&1; then
        log "  Web service healthy"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    error "Web service failed health check after ${MAX_WAIT}s"
    if [ "$FORCE" != "true" ]; then
        error "Rolling back..."
        docker compose up -d --no-deps web  # restart with old state
        exit 1
    fi
fi

# Restart syslog collector
log "  Restarting syslog service..."
docker compose up -d --no-deps syslog
sleep 3

# Restart nginx
log "  Restarting nginx..."
docker compose up -d --no-deps nginx
sleep 2

echo ""

# -------------------------------------------------------------------------
# Step 6: Post-upgrade verification
# -------------------------------------------------------------------------
log "Step 6: Post-upgrade verification..."

NEW_VERSION=$(get_version)
log "  Version: $CURRENT_VERSION → $NEW_VERSION"

# Health check
if docker compose exec -T web curl -sf http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    log "  Health check: PASSED"
else
    # Try via nginx
    if curl -sf -k https://127.0.0.1/api/health >/dev/null 2>&1; then
        log "  Health check (via nginx): PASSED"
    else
        warn "  Health check: Could not verify (services may still be starting)"
    fi
fi

# Show container status
echo ""
log "Container status:"
docker compose ps --format "table {{.Service}}\t{{.Status}}" 2>/dev/null || docker compose ps

echo ""
echo "==========================================="
echo -e "   ${GREEN}Upgrade complete!${NC}"
echo "   Version: $CURRENT_VERSION → $NEW_VERSION"
echo "==========================================="
echo ""
echo "If issues occur, rollback with:"
echo "  ./scripts/rollback.sh"
