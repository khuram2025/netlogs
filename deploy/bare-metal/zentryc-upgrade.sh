#!/bin/bash
# =============================================================================
# Zentryc Upgrade Script — Online (git pull) or Offline (package)
#
# Usage:
#   sudo zentryc-upgrade                              # Online git pull
#   sudo zentryc-upgrade /path/to/package.tar.gz      # Offline package
#   sudo zentryc-upgrade --skip-backup                 # Skip pre-upgrade backup
#   sudo zentryc-upgrade --skip-backup /path/to/pkg    # Both flags
#
# =============================================================================

set -euo pipefail

INSTALL_DIR="/opt/zentryc"
VENV_DIR="$INSTALL_DIR/venv"
ENV_FILE="$INSTALL_DIR/.env"
BACKUP_DIR="$INSTALL_DIR/backups"
SKIP_BACKUP=false
OFFLINE_PACKAGE=""

# Output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        -h|--help)
            echo "Usage: sudo zentryc-upgrade [--skip-backup] [/path/to/package.tar.gz]"
            echo ""
            echo "Options:"
            echo "  --skip-backup    Skip pre-upgrade backup"
            echo "  /path/to/pkg     Upgrade from offline package"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            if [[ -f "$1" ]]; then
                OFFLINE_PACKAGE="$1"
            else
                fail "Unknown option or file not found: $1"
            fi
            shift
            ;;
    esac
done

# =============================================================================
# Pre-flight
# =============================================================================
echo -e "${BLUE}━━━ Zentryc Upgrade ━━━${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (use sudo)"
fi

if [[ ! -f "$INSTALL_DIR/.installed" ]]; then
    fail "Zentryc is not installed at $INSTALL_DIR (run install.sh first)"
fi

if [[ ! -f "$ENV_FILE" ]]; then
    fail "Configuration not found at $ENV_FILE"
fi

# Get current version
OLD_VERSION=$(grep '__version__' "$INSTALL_DIR/fastapi_app/__version__.py" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
info "Current version: $OLD_VERSION"

# Disk space check
AVAIL_GB=$(df -BG "$INSTALL_DIR" | awk 'NR==2 {gsub("G",""); print $4}')
if [[ "$AVAIL_GB" -lt 2 ]]; then
    fail "Insufficient disk space: ${AVAIL_GB}GB available (need 2GB+)"
fi

# =============================================================================
# Backup
# =============================================================================
if [[ "$SKIP_BACKUP" == false ]]; then
    info "Creating pre-upgrade backup..."
    if [[ -x "$INSTALL_DIR/scripts/backup.sh" ]]; then
        BACKUP_FILE=$("$INSTALL_DIR/scripts/backup.sh" "$BACKUP_DIR" 2>/dev/null | tail -1)
        ok "Backup created: $BACKUP_FILE"
    else
        warn "Backup script not found — skipping backup"
    fi
else
    warn "Skipping backup (--skip-backup)"
fi

# =============================================================================
# Stop services
# =============================================================================
info "Stopping services..."
systemctl stop zentryc-syslog 2>/dev/null || true
systemctl stop zentryc-web 2>/dev/null || true
sleep 2
ok "Services stopped"

# =============================================================================
# Apply code update
# =============================================================================
if [[ -n "$OFFLINE_PACKAGE" ]]; then
    info "Applying offline package: $OFFLINE_PACKAGE"
    EXTRACT_DIR=$(mktemp -d)
    tar -xzf "$OFFLINE_PACKAGE" -C "$EXTRACT_DIR"

    if [[ -d "$EXTRACT_DIR/app" ]]; then
        CODE_SRC="$EXTRACT_DIR/app"
    else
        CODE_SRC="$EXTRACT_DIR"
    fi

    rsync -a --delete \
        --exclude='.env' \
        --exclude='logs/' \
        --exclude='venv/' \
        --exclude='backups/' \
        --exclude='.installed' \
        --exclude='wheels/' \
        "$CODE_SRC/" "$INSTALL_DIR/"

    # Copy wheels for pip install
    if [[ -d "$EXTRACT_DIR/wheels" ]]; then
        cp -r "$EXTRACT_DIR/wheels" "$INSTALL_DIR/_wheels"
    fi

    rm -rf "$EXTRACT_DIR"
    ok "Offline code applied"
else
    info "Pulling latest code via git..."
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        cd "$INSTALL_DIR"
        git fetch origin 2>/dev/null
        git reset --hard origin/main 2>/dev/null
        ok "Git pull complete"
    else
        fail "No .git directory found and no offline package provided"
    fi
fi

# =============================================================================
# Update dependencies
# =============================================================================
info "Updating Python dependencies..."

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel -q

# Pin bcrypt first
"$VENV_DIR/bin/pip" install "bcrypt==4.0.1" -q

if [[ -d "$INSTALL_DIR/_wheels" ]]; then
    "$VENV_DIR/bin/pip" install --no-index --find-links="$INSTALL_DIR/_wheels" \
        -r "$INSTALL_DIR/fastapi_app/requirements.txt" -q
    rm -rf "$INSTALL_DIR/_wheels"
else
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/fastapi_app/requirements.txt" -q
fi

# Re-pin bcrypt
"$VENV_DIR/bin/pip" install "bcrypt==4.0.1" -q

ok "Dependencies updated"

# =============================================================================
# Update systemd units (in case they changed)
# =============================================================================
info "Updating systemd units..."
BARE_METAL_DIR="$INSTALL_DIR/deploy/bare-metal"

if [[ -d "$BARE_METAL_DIR" ]]; then
    cp "$BARE_METAL_DIR/zentryc-web.service" /etc/systemd/system/ 2>/dev/null || true
    cp "$BARE_METAL_DIR/zentryc-syslog.service" /etc/systemd/system/ 2>/dev/null || true
    cp "$BARE_METAL_DIR/zentryc-disk-cleanup.service" /etc/systemd/system/ 2>/dev/null || true
fi

systemctl daemon-reload
ok "Systemd reloaded"

# =============================================================================
# Fix permissions
# =============================================================================
chown -R zentryc:zentryc "$INSTALL_DIR"
chmod 600 "$ENV_FILE"

# =============================================================================
# Start services
# =============================================================================
info "Starting zentryc-web..."
systemctl start zentryc-web

HEALTH_OK=false
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/api/health/simple > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    sleep 2
done

if [[ "$HEALTH_OK" == true ]]; then
    ok "Web service is healthy"
else
    warn "Web health check timed out — check: journalctl -u zentryc-web -f"
fi

info "Starting zentryc-syslog..."
systemctl start zentryc-syslog
sleep 2

if systemctl is-active --quiet zentryc-syslog; then
    ok "Syslog collector started"
else
    warn "Syslog may not have started — check: journalctl -u zentryc-syslog -f"
fi

# =============================================================================
# Summary
# =============================================================================
NEW_VERSION=$(grep '__version__' "$INSTALL_DIR/fastapi_app/__version__.py" 2>/dev/null | cut -d'"' -f2 || echo "unknown")

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Zentryc Upgrade Complete${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Version: $OLD_VERSION → $NEW_VERSION"
echo ""
echo "  Services:"
systemctl is-active zentryc-web 2>/dev/null && echo "    zentryc-web:    active" || echo "    zentryc-web:    inactive"
systemctl is-active zentryc-syslog 2>/dev/null && echo "    zentryc-syslog: active" || echo "    zentryc-syslog: inactive"
echo ""
