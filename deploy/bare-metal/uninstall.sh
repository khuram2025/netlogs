#!/bin/bash
# =============================================================================
# Zentryc Uninstaller
#
# Usage:
#   sudo ./uninstall.sh              # Full removal (including databases)
#   sudo ./uninstall.sh --keep-data  # Remove app but keep PostgreSQL/ClickHouse data
#
# =============================================================================

set -euo pipefail

INSTALL_DIR="/opt/zentryc"
SSL_DIR="/etc/ssl/zentryc"
SYSCTL_CONF="/etc/sysctl.d/99-zentryc.conf"
ZENTRYC_USER="zentryc"
KEEP_DATA=false

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
        --keep-data)
            KEEP_DATA=true
            shift
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--keep-data]"
            echo ""
            echo "Options:"
            echo "  --keep-data   Remove app but keep PostgreSQL/ClickHouse databases"
            echo "  -h, --help    Show this help"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

# Pre-flight
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (use sudo)"
fi

echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}  Zentryc Uninstaller${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "$KEEP_DATA" == true ]]; then
    echo "  Mode: Remove application, KEEP database data"
else
    echo "  Mode: FULL removal (including databases)"
fi
echo ""

read -rp "Are you sure you want to uninstall Zentryc? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

# =============================================================================
# 1. Stop and disable services
# =============================================================================
info "Stopping services..."

systemctl stop zentryc-syslog 2>/dev/null || true
systemctl stop zentryc-web 2>/dev/null || true
systemctl stop zentryc-disk-cleanup.timer 2>/dev/null || true
systemctl stop zentryc-disk-cleanup 2>/dev/null || true

systemctl disable zentryc-web 2>/dev/null || true
systemctl disable zentryc-syslog 2>/dev/null || true
systemctl disable zentryc-disk-cleanup.timer 2>/dev/null || true
systemctl disable zentryc-disk-cleanup 2>/dev/null || true

rm -f /etc/systemd/system/zentryc-web.service
rm -f /etc/systemd/system/zentryc-syslog.service
rm -f /etc/systemd/system/zentryc-disk-cleanup.service
rm -f /etc/systemd/system/zentryc-disk-cleanup.timer

systemctl daemon-reload
ok "Services stopped and removed"

# =============================================================================
# 2. Remove Nginx configuration
# =============================================================================
info "Removing Nginx configuration..."

rm -f /etc/nginx/sites-enabled/zentryc
rm -f /etc/nginx/sites-available/zentryc

if command -v nginx &>/dev/null && systemctl is-active --quiet nginx; then
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
fi

ok "Nginx config removed"

# =============================================================================
# 3. Remove database data (unless --keep-data)
# =============================================================================
if [[ "$KEEP_DATA" == false ]]; then
    info "Removing PostgreSQL database..."
    if command -v psql &>/dev/null; then
        sudo -u postgres psql -q -c "DROP DATABASE IF EXISTS zentryc;" 2>/dev/null || true
        sudo -u postgres psql -q -c "DROP USER IF EXISTS zentryc;" 2>/dev/null || true
        ok "PostgreSQL database removed"
    else
        warn "PostgreSQL not found — skipping"
    fi

    info "Removing ClickHouse data..."
    if command -v clickhouse-client &>/dev/null; then
        clickhouse-client --query "DROP USER IF EXISTS zentryc;" 2>/dev/null || true
        # Drop Zentryc-specific tables
        for table in syslogs audit_logs ioc_matches correlation_matches; do
            clickhouse-client --query "DROP TABLE IF EXISTS default.${table};" 2>/dev/null || true
        done
        ok "ClickHouse data removed"
    else
        warn "ClickHouse not found — skipping"
    fi
else
    info "Keeping database data (--keep-data)"
fi

# =============================================================================
# 4. Remove TLS certificates
# =============================================================================
info "Removing TLS certificates..."
rm -rf "$SSL_DIR"
ok "TLS certificates removed"

# =============================================================================
# 5. Remove sysctl configuration
# =============================================================================
info "Removing kernel tuning..."
rm -f "$SYSCTL_CONF"
sysctl --system > /dev/null 2>&1 || true
ok "Sysctl config removed"

# =============================================================================
# 6. Remove upgrade command
# =============================================================================
rm -f /usr/local/bin/zentryc-upgrade
ok "Upgrade command removed"

# =============================================================================
# 7. Remove UFW rules
# =============================================================================
if command -v ufw &>/dev/null; then
    info "Removing UFW rules..."
    ufw delete allow 514/udp 2>/dev/null || true
    # Keep 22, 80, 443 as they may be used by other services
    warn "Kept SSH/HTTP/HTTPS UFW rules (may be used by other services)"
fi

# =============================================================================
# 8. Remove application directory
# =============================================================================
info "Removing $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
ok "Application directory removed"

# =============================================================================
# 9. Remove system user
# =============================================================================
if id "$ZENTRYC_USER" &>/dev/null; then
    info "Removing system user '$ZENTRYC_USER'..."
    userdel "$ZENTRYC_USER" 2>/dev/null || true
    ok "System user removed"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Zentryc Uninstalled${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "$KEEP_DATA" == true ]]; then
    echo "  Application removed. Database data preserved."
    echo "  PostgreSQL: zentryc database still exists"
    echo "  ClickHouse: tables still exist"
else
    echo "  Full removal complete."
fi

echo ""
echo "  Note: PostgreSQL and ClickHouse server packages were NOT removed."
echo "  To remove them: sudo apt-get purge postgresql-16 clickhouse-server"
echo ""
